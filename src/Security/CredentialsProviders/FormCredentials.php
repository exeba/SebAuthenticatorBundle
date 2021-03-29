<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsProviders;

use Seb\AuthenticatorBundle\Security\CredentialsInterface;

class FormCredentials implements CredentialsInterface
{
    private $username;
    private $password;

    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getPassword()
    {
        return $this->password;
    }
}
