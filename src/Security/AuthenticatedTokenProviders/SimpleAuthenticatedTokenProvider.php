<?php


namespace Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviders;

use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;

class SimpleAuthenticatedTokenProvider implements AuthenticatedTokenProviderInterface
{

    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        return new PostAuthenticationGuardToken(
            $user,
            $providerKey,
            $user->getRoles()
        );
    }
}