<?php

namespace Bash\Bundle\OIDCDBundle\Exception;

class OidcdClientNotFoundException extends OidcdException
{
    public function __construct(string $name, \Throwable $previous = null)
    {
        parent::__construct(sprintf('Client "%s" does not exist.', $name), 0, $previous);
    }
}
