<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsProviders;

use Seb\AuthenticatorBundle\Security\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;

class FormCredentials extends PasswordCredentials implements CredentialsInterface
{
    private $username;

    public function __construct($username, $password)
    {
        parent::__construct($password);
        $this->username = $username;
    }

    public function getUsername()
    {
        return $this->username;
    }
}
