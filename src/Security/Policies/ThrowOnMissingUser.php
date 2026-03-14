<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

class ThrowOnMissingUser implements MissingUserPolicy
{
    public function userNotFound($credentials)
    {
        throw new UserNotFoundException($credentials->getUsername());
    }

    public function successfulAuthentication(UserInterface $user)
    {
        // NO-OP
    }
}
