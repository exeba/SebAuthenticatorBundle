<?php

namespace Seb\AuthenticatorBundle\Security\Authenticator;

use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

interface AuthenticatedTokenProviderInterface
{
    public function createAuthenticatedToken(Passport $passport, $providerKey);
}
