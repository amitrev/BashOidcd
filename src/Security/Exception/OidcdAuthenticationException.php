<?php

namespace Bash\Bundle\OIDCDBundle\Security\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class OidcdAuthenticationException extends AuthenticationException
{
    public function __construct(string $message, \Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
