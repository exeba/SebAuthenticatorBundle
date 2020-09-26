<?php

namespace Seb\AuthenticatorBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

interface CredentialsProviderInterface
{
    public function supports(Request $request);

    public function getCredentials(Request $request);

    public function supportsRememberMe();

    public function start(Request $request, AuthenticationException $authException = null);
}
