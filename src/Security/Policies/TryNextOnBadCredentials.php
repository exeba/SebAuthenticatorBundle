<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class TryNextOnBadCredentials implements BadCredentialsPolicy
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // Returning anything other than a Response object will not stop the authentication.
        return null;
    }
}
