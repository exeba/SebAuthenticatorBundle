<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

class ThrowOnMissingUser implements MissingUserPolicy
{
    public function userNotFound($credentials)
    {
        throw new UsernameNotFoundException($credentials['username']);
    }

    public function successfulAuthentication(UserInterface $user)
    {
        // NO-OP
    }
}
