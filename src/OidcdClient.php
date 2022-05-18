<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Exception\OidcdConfigurationException;
use Bash\Bundle\OIDCDBundle\Exception\OidcdConfigurationResolveException;
use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use Bash\Bundle\OIDCDBundle\Model\OidcdTokens;
use Bash\Bundle\OIDCDBundle\Model\OidcdUserData;
use Bash\Bundle\OIDCDBundle\Security\Exception\OidcdAuthenticationException;
use Exception;
use InvalidArgumentException;
use LogicException;
use phpseclib3\Crypt\RSA;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\String\Slugger\AsciiSlugger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class OidcdClient implements OidcdClientInterface
{
    protected ?array $configuration = null;
    protected HttpUtils $httpUtils;

    protected RequestStack $requestStack;
    protected ?CacheInterface $wellKnownCache;
    protected OidcdUrlFetcher $urlFetcher;
    protected OidcdSessionStorage $sessionStorage;
    protected OidcdJwtHelper $jwtHelper;
    protected string $wellKnownUrl;
    private ?string $cacheKey = null;
    private ?int $wellKnownCacheTime;
    private string $clientId;
    private string $clientSecret;
    private string $redirectRoute;
    private string $rememberMeParameter;

    public function __construct(
        RequestStack $requestStack,
        HttpUtils $httpUtils,
        ?CacheInterface $wellKnownCache,
        OidcdUrlFetcher $urlFetcher,
        OidcdSessionStorage $sessionStorage,
        OidcdJwtHelper $jwtHelper,
        string $wellKnownUrl,
        ?int $wellKnownCacheTime,
        string $clientId,
        string $clientSecret,
        string $redirectRoute,
        string $rememberMeParameter)
    {
        $this->rememberMeParameter = $rememberMeParameter;
        $this->redirectRoute = $redirectRoute;
        $this->clientSecret = $clientSecret;
        $this->clientId = $clientId;
        $this->wellKnownCacheTime = $wellKnownCacheTime;
        $this->wellKnownUrl = $wellKnownUrl;
        $this->jwtHelper = $jwtHelper;
        $this->sessionStorage = $sessionStorage;
        $this->urlFetcher = $urlFetcher;
        $this->wellKnownCache = $wellKnownCache;
        $this->requestStack = $requestStack;
        $this->httpUtils = $httpUtils;

        if (!class_exists(RSA::class)) {
            throw new RuntimeException('Unable to find phpseclib Crypt/RSA.php.  Ensure phpseclib3 is installed.');
        }

        if (!$this->wellKnownUrl || false === filter_var($this->wellKnownUrl, FILTER_VALIDATE_URL)) {
            throw new LogicException(sprintf('Invalid well known url (%s) for OIDC', $this->wellKnownUrl));
        }
    }

    public function authenticate(Request $request): OidcdTokens
    {
        if ($request->request->has('error')) {
            throw new OidcdAuthenticationException(sprintf('OIDC error: %s. Description: %s.', $request->request->get('error', ''), $request->request->get('error_description', '')));
        }

        if (!$code = $request->query->get('code')) {
            throw new OidcdAuthenticationException('Missing code in query');
        }
        if (!$state = $request->query->get('state')) {
            throw new OidcdAuthenticationException('Missing state in query');
        }

        if ($state !== $this->sessionStorage->getState()) {
            throw new OidcdAuthenticationException('Invalid session state');
        }

        $this->sessionStorage->clearState();

        return $this->verifyTokens($this->requestTokens('authorization_code', $code, $this->getRedirectUrl()));
    }

    public function refreshTokens(string $refreshToken): OidcdTokens
    {
        $this->sessionStorage->clearState();

        return $this->verifyTokens(
            $this->requestTokens('refresh_token', null, null, $refreshToken), false);
    }

    public function generateAuthorizationRedirect(?string $prompt = null, array $scopes = ['openid'], bool $forceRememberMe = false): RedirectResponse
    {
        $data = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->getRedirectUrl(),
            'scope' => implode(' ', $scopes),
            'state' => $this->generateState(),
            'nonce' => $this->generateNonce(),
        ];

        if ($prompt) {
            $validPrompts = ['none', 'login', 'consent', 'select_account', 'create'];
            if (!in_array($prompt, $validPrompts)) {
                throw new InvalidArgumentException(sprintf('The prompt parameter need to be one of ("%s"), but "%s" given', implode('", "', $validPrompts), $prompt));
            }

            $data['prompt'] = $prompt;
        }

        // Store remember me state
        $parameter = $this->requestStack->getCurrentRequest()->get($this->rememberMeParameter);
        $this->sessionStorage->storeRememberMe($forceRememberMe || 'true' === $parameter || 'on' === $parameter || '1' === $parameter || 'yes' === $parameter || true === $parameter);

        // Remove security session state
        $session = $this->requestStack->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);
        $session->remove(Security::LAST_USERNAME);

        return new RedirectResponse(sprintf('%s?%s', $this->getAuthorizationEndpoint(), http_build_query($data)));
    }

    public function retrieveUserInfo(OidcdTokens $tokens): OidcdUserData
    {
        $headers = ["Authorization: Bearer {$tokens->getAccessToken()}"];

        // Retrieve the user information and convert the encoding to UTF-8 to harden for surfconext UTF-8 bug
        $jsonData = $this->urlFetcher->fetchUrl($this->getUserinfoEndpoint(), null, $headers);
        $jsonData = mb_convert_encoding($jsonData, 'UTF-8');

        // Read the data
        try {
            $data = json_decode($jsonData, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new OidcdException('Error retrieving the user info from the endpoint.');
        }

        // Check data due
        if (!is_array($data)) {
            throw new OidcdException('Error retrieving the user info from the endpoint.');
        }

        return new OidcdUserData($data);
    }

    /** TODO: refactoring ?!?! */

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    protected function getAuthorizationEndpoint(): string
    {
        return $this->getConfigurationValue('authorization_endpoint');
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    protected function getIssuer(): string
    {
        return $this->getConfigurationValue('issuer');
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    protected function getJwktUri(): string
    {
        return $this->getConfigurationValue('jwks_uri');
    }

    protected function getRedirectUrl(): string
    {
        return $this->httpUtils->generateUri($this->requestStack->getCurrentRequest(), $this->redirectRoute);
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    protected function getTokenEndpoint(): string
    {
        return $this->getConfigurationValue('token_endpoint');
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     */
    protected function getTokenEndpointAuthMethods(): array
    {
        return $this->getConfigurationValue('token_endpoint_auth_methods_supported');
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     */
    protected function getUserinfoEndpoint(): string
    {
        return $this->getConfigurationValue('userinfo_endpoint');
    }

    private function generateNonce(): string
    {
        $value = $this->generateRandomString();

        $this->sessionStorage->storeNonce($value);

        return $value;
    }

    private function generateRandomString(): string
    {
        return md5(openssl_random_pseudo_bytes(25));
    }

    private function generateState(): string
    {
        $value = $this->generateRandomString();
        $this->sessionStorage->storeState($value);

        return $value;
    }

    /**
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    private function getConfigurationValue(string $key)
    {
        // Resolve the configuration
        $this->resolveConfiguration();

        if (!array_key_exists($key, $this->configuration)) {
            throw new OidcdConfigurationException($key);
        }

        return $this->configuration[$key];
    }

    /**
     * @throws OidcdException
     */
    private function requestTokens(string $grantType, string $code = null, string $redirectUrl = null, string $refreshToken = null): OidcdTokens
    {
        $params = [
            'grant_type' => $grantType,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        if (null !== $code) {
            $params['code'] = $code;
        }

        if (null !== $redirectUrl) {
            $params['redirect_uri'] = $redirectUrl;
        }

        if (null !== $refreshToken) {
            $params['refresh_token'] = $refreshToken;
        }

        // Use basic auth if offered
        $headers = [];
        if (in_array('client_secret_basic', $this->getTokenEndpointAuthMethods(), true)) {
            $headers = ['Authorization: Basic '.base64_encode(urlencode($this->clientId).':'.urlencode($this->clientSecret))];
            unset($params['client_secret']);
        }

        try {
            $jsonToken = json_decode($this->urlFetcher->fetchUrl($this->getTokenEndpoint(), $params, $headers), false, 512, JSON_THROW_ON_ERROR);
        } catch (OidcdConfigurationException|OidcdConfigurationResolveException|\JsonException $e) {
            throw new OidcdException('Parse json token.');
        }

        // Throw an error if the server returns one
        if (isset($jsonToken->error)) {
            if (isset($jsonToken->error_description)) {
                throw new OidcdAuthenticationException($jsonToken->error_description);
            }
            throw new OidcdAuthenticationException(sprintf('Got response: %s', $jsonToken->error));
        }

        return new OidcdTokens($jsonToken);
    }

    /** @throws OidcdException */
    private function verifyTokens(OidcdTokens $tokens, $verifyNonce = true): OidcdTokens
    {
        $claims = $this->jwtHelper->decodeJwt($tokens->getIdToken(), 1);

        if (!$this->jwtHelper->verifyJwtSignature($this->getJwktUri(), $tokens)) {
            throw new OidcdAuthenticationException('Unable to verify signature');
        }

        // If this is a valid claim
        if ($this->jwtHelper->verifyJwtClaims($this->getIssuer(), $claims, $tokens, $verifyNonce)) {
            return $tokens;
        }

        throw new OidcdAuthenticationException('Unable to verify JWT claims');
    }

    /**
     * @throws OidcdConfigurationResolveException|\Psr\Cache\InvalidArgumentException
     */
    private function resolveConfiguration(): void
    {
        if (null !== $this->configuration) {
            return;
        }

        if ($this->wellKnownCache && null !== $this->wellKnownCacheTime) {
            $this->cacheKey ??= '_bash_oidcd_client__'.(new AsciiSlugger('en'))->slug($this->wellKnownUrl);
            $config = $this->wellKnownCache->get($this->cacheKey, function (ItemInterface $item) {
                $item->expiresAfter($this->wellKnownCacheTime);

                return $this->retrieveWellKnownConfiguration();
            });
        } else {
            $config = $this->retrieveWellKnownConfiguration();
        }

        $this->configuration = $config;
    }

    /**
     * @throws OidcdConfigurationResolveException
     */
    private function retrieveWellKnownConfiguration(): array
    {
        try {
            $wellKnown = $this->urlFetcher->fetchUrl($this->wellKnownUrl);
        } catch (Exception $e) {
            throw new OidcdConfigurationResolveException(sprintf('Could not retrieve OIDC configuration from "%s".', $this->wellKnownUrl), 0, $e);
        }

        try {
            $config = json_decode($wellKnown, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new OidcdConfigurationResolveException(sprintf('Could not parse OIDC configuration. Response data: "%s"', $wellKnown));
        }

        if (null === $config) {
            throw new OidcdConfigurationResolveException(sprintf('Could not parse OIDC configuration. Response data: "%s"', $wellKnown));
        }

        return $config;
    }
}
