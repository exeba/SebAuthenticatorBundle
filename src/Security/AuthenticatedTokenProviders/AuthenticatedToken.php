<?php

namespace Seb\AuthenticatorBundle\Security\Authenticator;

use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;

class AuthenticatedToken extends PreAuthenticatedToken
{

    public function __construct($user, $firewallName, $roles = [])
    {
        parent::__construct($user, $firewallName, $roles);
    }
}
