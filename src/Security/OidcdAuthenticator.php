<?php

namespace Bash\Bundle\OIDCDBundle\Security;

use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use Bash\Bundle\OIDCDBundle\OidcdClientInterface;
use Bash\Bundle\OIDCDBundle\OidcdSessionStorage;
use Bash\Bundle\OIDCDBundle\Security\Exception\OidcdAuthenticationException;
use Bash\Bundle\OIDCDBundle\Security\Exception\UnsupportedManagerException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class OidcdAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    private HttpUtils $httpUtils;
    private OidcdUserProviderInterface $oidcUserProvider;
    private OidcdClientInterface $oidcClient;
    private OidcdSessionStorage $sessionStorage;
    private AuthenticationSuccessHandlerInterface $successHandler;
    private AuthenticationFailureHandlerInterface $failureHandler;
    private string $checkPath;
    private string $loginPath;
    private string $userIdentifierProperty;
    private bool $enableRememberMe;

    public function __construct(
        HttpUtils $httpUtils,
        OidcdClientInterface $oidcClient,
        OidcdSessionStorage $sessionStorage,
        OidcdUserProviderInterface $oidcUserProvider,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        string $checkPath,
        string $loginPath,
        string $userIdentifierProperty,
        bool $enableRememberMe)
    {
        $this->enableRememberMe = $enableRememberMe;
        $this->userIdentifierProperty = $userIdentifierProperty;
        $this->loginPath = $loginPath;
        $this->checkPath = $checkPath;
        $this->failureHandler = $failureHandler;
        $this->successHandler = $successHandler;
        $this->sessionStorage = $sessionStorage;
        $this->oidcClient = $oidcClient;
        $this->oidcUserProvider = $oidcUserProvider;
        $this->httpUtils = $httpUtils;
    }

    public function supports(Request $request): ?bool
    {
        return
            $this->httpUtils->checkRequestPath($request, $this->checkPath)
            && $request->query->has('code')
            && $request->query->has('state');
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $authData = $this->oidcClient->authenticate($request);

            // TODO: if authData->idToken exists then use getUserDataByToken();
            $idToken = $authData->getIdToken();
            if ($idToken !== '') {
                $userData = $this->oidcClient->getUserDataByToken($idToken, $authData->getRefreshToken());
            }

            if (!isset($userData)) {
                $userData = $this->oidcClient->retrieveUserInfo($authData);
            }

            if (!$userIdentifier = $userData->getUserDataString($this->userIdentifierProperty)) {
                throw new UserNotFoundException(sprintf('User identifier property (%s) yielded empty user identifier', $this->userIdentifierProperty));
            }
            $this->oidcUserProvider->ensureUserExists($userIdentifier, $userData);

            $passport = new SelfValidatingPassport(new UserBadge(
                $userIdentifier,
                fn (string $userIdentifier) => $this->oidcUserProvider->loadOidcUser($userIdentifier),
            ));
            $passport->setAttribute(OidcdToken::AUTH_DATA_ATTR, $authData);
            $passport->setAttribute(OidcdToken::USER_DATA_ATTR, $userData);

            if ($this->enableRememberMe && $this->sessionStorage->getRememberMe()) {
                $passport->addBadge((new RememberMeBadge())->enable());
                $this->sessionStorage->clearRememberMe();
            }

            return $passport;
        } catch (OidcdException $e) {
            throw new OidcdAuthenticationException('OIDC authentication failed', $e);
        }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

        $redirectTarget = $request->getSession()->getBag('attributes')->get('bash_target');

        if (null !== $redirectTarget && false === strpos($redirectTarget, 'login')) {
            return new RedirectResponse($redirectTarget);
        }

        return $response;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new OidcdToken($passport, $firewallName);
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        throw new UnsupportedManagerException();
    }
}
