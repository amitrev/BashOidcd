<?php

namespace Bash\Bundle\OIDCDBundle\Security;

use Bash\Bundle\OIDCDBundle\Model\OidcdTokens;
use Bash\Bundle\OIDCDBundle\Model\OidcdUserData;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class OidcdToken extends PostAuthenticationToken
{
    public const USER_DATA_ATTR = 'user_data';
    public const AUTH_DATA_ATTR = 'auth_data';

    public function __construct(Passport $passport, string $firewallName)
    {
        parent::__construct($passport->getUser(), $firewallName, $passport->getUser()->getRoles());

        $this->setAttribute(self::AUTH_DATA_ATTR, $passport->getAttribute(self::AUTH_DATA_ATTR));
        $this->setAttribute(self::USER_DATA_ATTR, $passport->getAttribute(self::USER_DATA_ATTR));
    }

    public function getAuthData(): OidcdTokens
    {
        return $this->getAttribute(self::AUTH_DATA_ATTR);
    }

    public function getUserData(): OidcdUserData
    {
        return $this->getAttribute(self::USER_DATA_ATTR);
    }
}
