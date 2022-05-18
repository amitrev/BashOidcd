<?php

namespace Bash\Bundle\OIDCDBundle\Security;

use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use Bash\Bundle\OIDCDBundle\Model\OidcdUserData;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface OidcdUserProviderInterface extends UserProviderInterface
{
    /** @throws OidcdException Can be thrown when the user cannot be created */
    public function ensureUserExists(string $userIdentifier, OidcdUserData $userData);

    public function loadOidcUser(string $userIdentifier): UserInterface;
}
