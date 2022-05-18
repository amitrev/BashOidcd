<?php

namespace Bash\Bundle\OIDCDBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $builder = new TreeBuilder('bash_oidcd_bundle');

        $builder
            ->getRootNode()
                ->children()
                    ->arrayNode('clients')->prototype('variable')->end()->end()
                ->end()
            ->end()
        ;

        return $builder;
    }
}
