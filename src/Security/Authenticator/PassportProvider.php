<?php

namespace Seb\AuthenticatorBundle\Security\Authenticator;

use Seb\AuthenticatorBundle\Security\CredentialsCheckerInterface;
use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Seb\AuthenticatorBundle\Security\PassportProviderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class PassportProvider implements PassportProviderInterface
{
    private $userProvider;
    private $credentialsChecker;
    private $missingUserPolicy;

    public function __construct(
        UserProviderInterface $userProvider,
        CredentialsCheckerInterface $credentialsChecker,
        MissingUserPolicy $missingUserPolicy)
    {
        $this->userProvider = $userProvider;
        $this->credentialsChecker = $credentialsChecker;
        $this->missingUserPolicy = $missingUserPolicy;
    }

    public function authenticate(CredentialsInterface $credentials): Passport
    {
        $user = $this->loadUser($credentials);
        if (!$this->credentialsChecker->checkCredentials($credentials, $user)) {
            throw new BadCredentialsException();
        }
        $this->missingUserPolicy->successfulAuthentication($user);

        return $this->createPassport($user, $credentials);
    }

    private function createPassport(UserInterface $user, CredentialsInterface $credentials)
    {
        $userBadge = $this->createUserBadge($user);

        return new Passport($userBadge, $credentials);
    }

    private function createUserBadge(UserInterface $user)
    {
        return new UserBadge($user->getUserIdentifier(), function () use ($user) { return $user; });
    }

    private function loadUser(CredentialsInterface $credentials)
    {
        if (! ($credentials instanceof \Seb\AuthenticatorBundle\Security\CredentialsInterface)) {
            return $this->missingUserPolicy->userNotFound($credentials);
        }

        try {
            return $this->userProvider->loadUserByIdentifier($credentials->getUsername());
        } catch (UserNotFoundException $e) {
            return $this->missingUserPolicy->userNotFound($credentials);
        }
    }
}
