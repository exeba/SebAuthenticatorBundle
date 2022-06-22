<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\HttpUtils;

class SimpleRedirect implements SuccessfulAuthenticationPolicy
{
    private $httpUtils;
    private $pagePath;

    public function __construct(HttpUtils $httpUtils, $pagePath = 'homepage')
    {
        $this->httpUtils = $httpUtils;
        $this->pagePath = $pagePath;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return $this->httpUtils->createRedirectResponse($request, $this->pagePath);
    }
}
