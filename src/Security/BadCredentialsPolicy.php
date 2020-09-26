<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

interface BadCredentialsPolicy
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception);
}
