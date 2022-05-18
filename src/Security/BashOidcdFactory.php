<?php

namespace Bash\Bundle\OIDCDBundle\Security\Factory;

use Bash\Bundle\OIDCDBundle\DependencyInjection\BashOIDCDExtension;
use Bash\Bundle\OIDCDBundle\Security\Exception\UnsupportedManagerException;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class BashOidcdFactory extends AbstractFactory implements AuthenticatorFactoryInterface
{
    public const PRIORITY = -5;

    public function __construct()
    {
        // Remove unused options
        unset($this->options['use_forward'], $this->options['require_previous_session']);

        // Set extra options
        $this->addOption('client', 'default');
        $this->addOption('user_identifier_property', 'sub');
        $this->addOption('enable_remember_me', false);
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getKey(): string
    {
        return 'oidcd';
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $authenticatorId = sprintf('%s.%s', BashOIDCDExtension::AUTHENTICATOR_ID, $firewallName);
        $container
            ->setDefinition($authenticatorId, new ChildDefinition(BashOIDCDExtension::AUTHENTICATOR_ID))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument(new Reference(sprintf('%s.%s', BashOIDCDExtension::CLIENT_ID, $config['client'])))
            ->addArgument(new Reference(sprintf('%s.%s', BashOIDCDExtension::SESSION_STORAGE_ID, $config['client'])))
            ->addArgument(new Reference($userProviderId))
            ->addArgument(new Reference($this->createAuthenticationSuccessHandler($container, $firewallName, $config)))
            ->addArgument(new Reference($this->createAuthenticationFailureHandler($container, $firewallName, $config)))
            ->addArgument($config['check_path'])
            ->addArgument($config['login_path'])
            ->addArgument($config['user_identifier_property'])
            ->addArgument($config['enable_remember_me']);

        return $authenticatorId;
    }

    /**
     * The following methods are required for Symfony 5.4 compatibility, but are not used.
     *
     * @todo: Remove when dropping support for Symfony 5.4
     */
    protected function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        throw new UnsupportedManagerException();
    }

    protected function getListenerId(): string
    {
        throw new UnsupportedManagerException();
    }

    public function getPosition(): string
    {
        throw new UnsupportedManagerException();
    }
}
