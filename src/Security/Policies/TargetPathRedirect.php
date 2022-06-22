<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class TargetPathRedirect implements SuccessfulAuthenticationPolicy
{
    use TargetPathTrait;

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        if ($targetPath) {
            return new RedirectResponse($targetPath);
        }

        return null;
    }
}
