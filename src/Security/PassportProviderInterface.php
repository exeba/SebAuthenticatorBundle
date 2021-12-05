<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

interface PassportProviderInterface
{
    public function authenticate(CredentialsInterface $credentials): Passport;
}
