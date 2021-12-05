<?php

namespace Seb\AuthenticatorBundle\Security\Authenticator;

use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviders\AuthenticatedToken;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class SimpleAuthenticatedTokenProvider implements AuthenticatedTokenProviderInterface
{
    public function createAuthenticatedToken(Passport $passport, $providerKey)
    {
        return new AuthenticatedToken(
            $passport->getUser(),
            $providerKey,
            $passport->getUser()->getRoles()
        );
    }
}
