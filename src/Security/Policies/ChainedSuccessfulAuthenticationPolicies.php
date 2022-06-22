<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class ChainedSuccessfulAuthenticationPolicies implements SuccessfulAuthenticationPolicy
{
    private $policies;

    public function __construct(SuccessfulAuthenticationPolicy ...$policies)
    {
        $this->policies = $policies;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        foreach ($this->policies as $policy) {
            $response = $policy->onAuthenticationSuccess($request, $token, $providerKey);
            if ($response) {
                return $response;
            }
        }

        return null;
    }
}
