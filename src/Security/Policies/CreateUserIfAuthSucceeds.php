<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Seb\AuthenticatorBundle\Security\UserManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class CreateUserIfAuthSucceeds implements MissingUserPolicy
{
    private $userManager;

    public function __construct(UserManagerInterface $userManager)
    {
        $this->userManager = $userManager;
    }

    public function userNotFound($credentials)
    {
        return $this->userManager->createUser($credentials);
    }

    public function successfulAuthentication(UserInterface $user)
    {
        $this->userManager->persistUser($user);
    }
}
