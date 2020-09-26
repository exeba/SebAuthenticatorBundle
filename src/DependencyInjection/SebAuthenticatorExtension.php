<?php

namespace Seb\AuthenticatorBundle\DependencyInjection;

use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviders\SimpleAuthenticatedTokenProvider;
use Seb\AuthenticatorBundle\Security\CredentialsCheckers\ImapCredentialsChecker;
use Seb\AuthenticatorBundle\Security\CredentialsCheckers\LocalCredentialsChecker;
use Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentialsProvider;
use Seb\AuthenticatorBundle\Security\Guard\Authenticator;
use Seb\AuthenticatorBundle\Security\Policies\CreateUserIfAuthSucceeds;
use Seb\AuthenticatorBundle\Security\Policies\RedirectOnBadCredentials;
use Seb\AuthenticatorBundle\Security\Policies\ThrowOnMissingUser;
use Seb\AuthenticatorBundle\Security\Policies\TryNextOnBadCredentials;
use Seb\AuthenticatorBundle\Utils\FOSUserManagerBridge;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;

class SebAuthenticatorExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('seb_authenticator.login_page', $config['login_page']);

        foreach ($config['guards'] as $guardName => $guardConfig) {
            $definition = $this->formGuard($guardConfig);
            $container->setDefinition("seb_authenticator.guards.$guardName", $definition);
        }
    }

    public function formGuard(array $guardConfig)
    {
        $guard = new Definition(Authenticator::class);
        $guard->setArgument(0, $this->credentialsProviderDefinition($guardConfig));
        $guard->setArgument(1, $this->credentialsCheckerDefinition($guardConfig));
        $guard->setArgument(2, $this->missingUserPolicyDefinition($guardConfig));
        $guard->setArgument(3, $this->badCredentialsPolicyDefinition($guardConfig));
        $guard->setArgument(4, new Definition(SimpleAuthenticatedTokenProvider::class));

        return $guard;
    }

    public function credentialsProviderDefinition(array $guardConfig)
    {
        if (array_key_exists('form_login', $guardConfig)) {
            $credentials = new Definition(FormCredentialsProvider::class);
            $credentials->setAutowired(true);
            $credentials->setArgument(1, $guardConfig['form_login'] ?? []);

            return $credentials;
        }

        throw new \Exception('Missing credentials provider configuration');
    }

    public function credentialsCheckerDefinition(array $guardConfig)
    {
        if (array_key_exists('local_credentials', $guardConfig)) {
            $checker = new Definition(LocalCredentialsChecker::class);
            $checker->setAutowired(true);

            return $checker;
        }

        if (array_key_exists('imap_credentials', $guardConfig)) {
            $checker = new Definition(ImapCredentialsChecker::class);
            $checker->setArgument(0, $guardConfig['imap_credentials']['mailbox']);

            return $checker;
        }

        throw new \Exception('Missing credentials checker configuration');
    }

    public function missingUserPolicyDefinition(array $guardConfig)
    {
        $policy = $guardConfig['missing_user'] ?? 'fail';
        if ('create' === $policy) {
            $missingUser = new Definition(CreateUserIfAuthSucceeds::class);
        } else {
            $missingUser = new Definition(ThrowOnMissingUser::class);
        }
        $missingUser->setAutowired(true);

        return $missingUser;
    }

    public function badCredentialsPolicyDefinition(array $guardConfig)
    {
        $policy = $guardConfig['bad_credentials'] ?? 'redirect';
        if ('try_next' === $policy) {
            return new Definition(TryNextOnBadCredentials::class);
        } else {
            $badCredentials = new Definition(RedirectOnBadCredentials::class);
            $badCredentials->setAutowired(true);
            $badCredentials->setArgument(0, '%seb_authenticator.login_page%');

            return $badCredentials;
        }
    }

    public function getAlias()
    {
        return 'seb_authenticator';
    }
}
