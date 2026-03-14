<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

class RedirectOnBadCredentials implements BadCredentialsPolicy
{
    public $redirectRoute;
    public $httpUtils;

    public function __construct($redirectRoute, HttpUtils $httpUtils)
    {
        $this->redirectRoute = $redirectRoute;
        $this->httpUtils = $httpUtils;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);
        }

        return $this->httpUtils->createRedirectResponse($request, $this->redirectRoute);
    }
}
