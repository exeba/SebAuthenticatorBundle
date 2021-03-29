<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface AuthenticatedTokenProviderInterface
{
    public function createAuthenticatedToken(UserInterface $user, $providerKey);
}
