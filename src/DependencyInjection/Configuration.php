<?php

namespace Bash\Bundle\OIDCDBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('bash_oidcd');

        $treeBuilder->getRootNode()
            ->fixXmlConfig('client')
            ->children()
            ->scalarNode('default_client')
            ->info('The default client to use')
            ->defaultValue('default')
            ->end()
            ->arrayNode('clients')
            ->useAttributeAsKey('name')
            ->requiresAtLeastOneElement()
            ->arrayPrototype()
            ->children()
            ->scalarNode('well_known_url')
            ->isRequired()
            ->end() // well_known_url
            ->scalarNode('well_known_cache_time')
            ->defaultValue(3600)
            ->validate()
            ->ifTrue(fn ($value) => null !== $value && !is_int($value))
            ->thenInvalid('Must be either null or an integer value')
            ->end()
            ->end() // well_known_cache_time
            ->scalarNode('client_id')
            ->isRequired()
            ->end() // client_id
            ->scalarNode('client_secret')
            ->isRequired()
            ->end() // client_secret
            ->scalarNode('redirect_route')
            ->defaultValue('/login_check')
            ->end() // redirect_route
            ->scalarNode('site_name')
            ->isRequired()
            ->end() // site_name
            ->arrayNode('custom_client_headers')
            ->scalarPrototype()->end()
            ->end() // custom_client_headers
            ->scalarNode('remember_me_parameter')
            ->defaultValue('_remember_me')
            ->end() // remember_me_parameter
            ->end() // array prototype children
            ->end() // array prototype
            ->end() // clients
            ->end(); // root children

        return $treeBuilder;
    }
}
