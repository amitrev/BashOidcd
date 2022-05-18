<?php

namespace Bash\Bundle\OIDCDBundle\Exception;

class OidcdConfigurationException extends OidcdException
{
    public function __construct(string $key)
    {
        parent::__construct(sprintf('Configuration key "%s" does not exist.', $key));
    }
}
