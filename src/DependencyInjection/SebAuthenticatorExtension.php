<?php

namespace Seb\AuthenticatorBundle\DependencyInjection;

use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviders\SimpleAuthenticatedTokenProvider as GuardAuthenticatedTokenProvider;
use Seb\AuthenticatorBundle\Security\Authenticator\Authenticator;
use Seb\AuthenticatorBundle\Security\Authenticator\PassportProvider;
use Seb\AuthenticatorBundle\Security\Authenticator\SimpleAuthenticatedTokenProvider;
use Seb\AuthenticatorBundle\Security\CredentialsCheckers\LocalCredentialsChecker;
use Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentialsProvider;
use Seb\AuthenticatorBundle\Security\Guard\Authenticator as GuardAuthenticator;
use Seb\AuthenticatorBundle\Security\Policies\CreateUserIfAuthSucceeds;
use Seb\AuthenticatorBundle\Security\Policies\RedirectOnBadCredentials;
use Seb\AuthenticatorBundle\Security\Policies\TargetPathOrHomePageRedirect;
use Seb\AuthenticatorBundle\Security\Policies\ThrowOnMissingUser;
use Seb\AuthenticatorBundle\Security\Policies\TryNextOnBadCredentials;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

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

        foreach ($config['authenticators'] as $authenticatorName => $authenticatorConfig) {
            $definition = $this->formAuthenticator($authenticatorConfig);
            $container->setDefinition("seb_authenticator.authenticators.$authenticatorName", $definition);
        }
    }

    public function formGuard(array $guardConfig)
    {
        $guard = new Definition(GuardAuthenticator::class);
        $guard->setArgument(0, $this->credentialsProviderDefinition($guardConfig));
        $guard->setArgument(1, $this->credentialsCheckerDefinition($guardConfig));
        $guard->setArgument(2, $this->missingUserPolicyDefinition($guardConfig));
        $guard->setArgument(3, $this->badCredentialsPolicyDefinition($guardConfig));
        $guard->setArgument(4, $this->successfulAuthenticationPolicyDefinition($guardConfig));
        $guard->setArgument(5, new Definition(GuardAuthenticatedTokenProvider::class));

        return $guard;
    }

    public function formAuthenticator(array $authenticatorConfig)
    {
        $authenticator = new Definition(Authenticator::class);
        $authenticator->setArgument(0, $this->credentialsProviderDefinition($authenticatorConfig));
        $authenticator->setArgument(1, $this->passportProviderDefinition($authenticatorConfig));
        $authenticator->setArgument(2, new Definition(SimpleAuthenticatedTokenProvider::class));
        $authenticator->setArgument(3, $this->successfulAuthenticationPolicyDefinition($authenticatorConfig));
        $authenticator->setArgument(4, $this->badCredentialsPolicyDefinition($authenticatorConfig));

        return $authenticator;
    }

    public function passportProviderDefinition(array $authenticatorConfig)
    {
        $passportProvider = new Definition(PassportProvider::class);
        // FIXME: This parameter is probably useless, is shoul be possible to get it from firewall config
        if (array_key_exists('user_provider', $authenticatorConfig)) {
            $passportProvider->setArgument(0, new Reference("security.user.provider.concrete.{$authenticatorConfig['user_provider']}"));
        } else {
            $passportProvider->setAutowired(true);
        }
        $passportProvider->setArgument(1, $this->credentialsCheckerDefinition($authenticatorConfig));
        $passportProvider->setArgument(2, $this->missingUserPolicyDefinition($authenticatorConfig));

        return $passportProvider;
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

    public function successfulAuthenticationPolicyDefinition(array $guardConfig)
    {
        $successfulAuthentication = new Definition(TargetPathOrHomePageRedirect::class);
        $successfulAuthentication->setAutowired(true);

        return $successfulAuthentication;
    }

}
