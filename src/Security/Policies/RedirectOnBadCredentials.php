<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;

class RedirectOnBadCredentials implements BadCredentialsPolicy
{
    public $redirectRoute;
    public $urlGenerator;

    public function __construct($redirectRoute, UrlGeneratorInterface $urlGenerator)
    {
        $this->redirectRoute = $redirectRoute;
        $this->urlGenerator = $urlGenerator;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->buildRedirectUrl());
    }

    private function buildRedirectUrl()
    {
        if ('/' === $this->redirectRoute[0]) {
            return $this->redirectRoute;
        } else {
            return $this->urlGenerator->generate($this->redirectRoute);
        }
    }
}
