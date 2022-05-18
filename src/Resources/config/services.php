<?php

use Bash\Bundle\OIDCDBundle\DependencyInjection\BashOIDCDExtension;
use Bash\Bundle\OIDCDBundle\OidcdClient;
use Bash\Bundle\OIDCDBundle\OidcdClientLocator;
use Bash\Bundle\OIDCDBundle\OidcdJwtHelper;
use Bash\Bundle\OIDCDBundle\OidcdSessionStorage;
use Bash\Bundle\OIDCDBundle\OidcdUrlFetcher;
use Bash\Bundle\OIDCDBundle\Security\OidcdAuthenticator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Contracts\Cache\CacheInterface;

return static function (ContainerConfigurator $configurator): void {
    $configurator->services()
      ->set(BashOIDCDExtension::AUTHENTICATOR_ID, OidcdAuthenticator::class)
        ->abstract()

      ->set(BashOIDCDExtension::URL_FETCHER_ID, OidcdUrlFetcher::class)
        ->abstract()

      ->set(BashOIDCDExtension::SESSION_STORAGE_ID, OidcdSessionStorage::class)
      ->args([
          service(RequestStack::class),
      ])
      ->abstract()

      ->set(BashOIDCDExtension::JWT_HELPER_ID, OidcdJwtHelper::class)
        ->abstract()

      ->set(BashOIDCDExtension::CLIENT_ID, OidcdClient::class)
        ->args([
            service(RequestStack::class),
            service(HttpUtils::class),
            service(CacheInterface::class)->nullOnInvalid(),
        ])
        ->abstract()

      ->set(BashOIDCDExtension::CLIENT_LOCATOR_ID, OidcdClientLocator::class)
      ->alias(OidcdClientLocator::class, BashOIDCDExtension::CLIENT_LOCATOR_ID)
  ;
};
