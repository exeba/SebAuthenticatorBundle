<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsCheckers;

use Seb\AuthenticatorBundle\Security\CredentialsCheckerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class LocalCredentialsChecker implements CredentialsCheckerInterface
{
    private $passwordEncoder;

    public function __construct(UserPasswordHasherInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if ($user instanceof PasswordAuthenticatedUserInterface) {
            return $this->passwordEncoder->isPasswordValid($user, $credentials->getPassword());
        }

        return false;
    }
}
