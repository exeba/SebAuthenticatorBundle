<?php


namespace Seb\AuthenticatorBundle\Security;


use Symfony\Component\Security\Core\User\UserInterface;

interface UserManagerInterface
{
    public function createUser($userData);

    public function persistUser(UserInterface $user);
}