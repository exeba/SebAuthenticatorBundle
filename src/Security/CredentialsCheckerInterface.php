<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface CredentialsCheckerInterface
{
    public function checkCredentials($credentials, UserInterface $user);
}
