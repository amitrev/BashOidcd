<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Exception\OidcdClientNotFoundException;
use Psr\Container\ContainerInterface;
use Throwable;

class OidcdClientLocator
{
    private ContainerInterface $locator;
    private string $defaultClient;

    public function __construct(ContainerInterface $locator, string $defaultClient)
    {
        $this->defaultClient = $defaultClient;
        $this->locator = $locator;
    }

    /** @throws OidcdClientNotFoundException */
    public function getClient(string $name = null): OidcdClientInterface
    {
        $name = $name ?? $this->defaultClient;
        if (!$this->locator->has($name)) {
            throw new OidcdClientNotFoundException($name);
        }

        try {
            return $this->locator->get($name);
        } catch (Throwable $e) {
            throw new OidcdClientNotFoundException($name, $e);
        }
    }
}
