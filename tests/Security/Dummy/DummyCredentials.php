<?php


namespace Seb\AuthenticatorBundle\Tests\Security\Dummy;


use Seb\AuthenticatorBundle\Security\CredentialsInterface;

class DummyCredentials implements CredentialsInterface
{

    private $username;

    public function __construct($username)
    {
        $this->username = $username;
    }

    public function getUsername()
    {
        return $this->username;
    }
}
