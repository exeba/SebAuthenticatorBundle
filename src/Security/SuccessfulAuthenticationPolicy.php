<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

interface SuccessfulAuthenticationPolicy
{
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey);
}
