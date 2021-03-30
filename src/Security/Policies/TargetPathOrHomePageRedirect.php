<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class TargetPathOrHomePageRedirect implements SuccessfulAuthenticationPolicy
{
    use TargetPathTrait;

    private $httpUtils;
    private $homePagePath;

    public function __constructor(HttpUtils $httpUtils, $homePagePath = 'homepage')
    {
        $this->httpUtils = $httpUtils;
        $this->homePagePath = $homePagePath;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        if ($targetPath) {
            return new RedirectResponse($targetPath);
        } else {
            return $this->httpUtils->createRedirectResponse($request, $this->homePagePath);
        }
    }
}
