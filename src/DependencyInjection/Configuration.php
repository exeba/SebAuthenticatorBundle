<?php

namespace Seb\AuthenticatorBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
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

        $config = $rootNode->children()
            ->scalarNode('login_page')->defaultValue('/login')->end();
        $config = $this->authConfig($config->arrayNode('guards'))->end();
        $this->authConfig($config->arrayNode('authenticators'))->end();

        return $treeBuilder;
    }

    private function authConfig(ArrayNodeDefinition $def)
    {
        return $def->useAttributeAsKey('name')
            ->arrayPrototype()
                ->children()
                    ->scalarNode('user_provider')->end()
                    ->arrayNode('form_login')
                        ->children()
                            ->scalarNode('username_parameter')->end()
                            ->scalarNode('password_parameter')->end()
                            ->scalarNode('csrf_parameter')->end()
                            ->scalarNode('login_path')->end()
                            ->scalarNode('login_check_path')->end()
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
            ->end();
    }
}
