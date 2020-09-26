<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface MissingUserPolicy
{
    public function userNotFound($credentials);

    public function successfulAuthentication(UserInterface $user);
}
