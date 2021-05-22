<?php

namespace Seb\AuthenticatorBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        if (method_exists(TreeBuilder::class, 'getRootNode')) {
            $treeBuilder = new TreeBuilder('seb_authenticator');
            $rootNode = $treeBuilder->getRootNode();
        } else {
            // Deprecated in Symfony 4.2
            $treeBuilder = new TreeBuilder();
            $rootNode = $treeBuilder->root('seb_authenticator');
        }

        $rootNode
            ->children()
                ->scalarNode('login_page')->defaultValue('/login')->end()
                ->arrayNode('guards')
                    ->useAttributeAsKey('name')
                        ->arrayPrototype()
                            ->children()
                                ->arrayNode('form_login')
                                    ->children()
                                        ->scalarNode('username_parameter')->end()
                                        ->scalarNode('password_parameter')->end()
                                        ->scalarNode('csrf_parameter')->end()
                                        ->scalarNode('login_path')->end()
                                        ->scalarNode('login_check_path')->end()
                                    ->end()
                                ->end()
                                ->arrayNode('imap_credentials')
                                    ->children()
                                        ->scalarNode('mailbox')->end()
                                    ->end()
                                ->end()
                                ->variableNode('local_credentials')->end()
                                ->enumNode('bad_credentials')
                                    ->values(['try_next', 'redirect'])
                                ->end()
                                ->enumNode('missing_user')
                                    ->values(['create', 'fail'])
                                ->end()
                                ->scalarNode('username')->end()
                                ->scalarNode('password')->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
