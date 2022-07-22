<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Exception\OidcdConfigurationException;
use Bash\Bundle\OIDCDBundle\Exception\OidcdConfigurationResolveException;
use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use Bash\Bundle\OIDCDBundle\Model\OidcdTokens;
use Bash\Bundle\OIDCDBundle\Model\OidcdUserData;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

interface OidcdClientInterface
{
    /**
     * Authenticate the incoming request.
     *
     * @throws OidcdException
     */
    public function authenticate(Request $request): OidcdTokens;

    /**
     * Use an existing refresh token to retrieve new tokens from the OIDC provider.
     *
     * @throws OidcdException
     */
    public function refreshTokens(string $refreshToken): OidcdTokens;

    /**
     * Create the redirect that should be followed in order to authorize.
     *
     * @param string|null $prompt One of 'none', 'login', 'consent', 'select_account' or 'create'
     *                            If null or not supplied, the parameter will be omitted from the request
     *                            Note that 'create' is currently in draft and might not be supported by every implementation
     * @param string[]    $scopes An array of scopes to request
     *                            If not supplied it will default to openid
     *
     * @throws OidcdConfigurationException
     * @throws OidcdConfigurationResolveException
     */
    public function generateAuthorizationRedirect(?string $prompt = null, array $scopes = ['offline_access', 'openid', 'fields', 'email']): RedirectResponse;

    /**
     * Retrieve the user information.
     *
     * @throws OidcdException
     */
    public function retrieveUserInfo(OidcdTokens $tokens): OidcdUserData;

    /**
     * Retrieve the user information.
     */
    public function getUserDataByToken(string $idToken): ?OidcdUserData;
}
