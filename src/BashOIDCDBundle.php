<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Security\BashOidcdFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class BashOIDCDBundle extends Bundle
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        assert($extension instanceof SecurityExtension);
        $extension->addAuthenticatorFactory(new BashOidcdFactory());
    }
}
