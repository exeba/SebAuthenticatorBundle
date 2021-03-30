<?php

namespace Seb\AuthenticatorBundle\Security\Guard;

use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviderInterface;
use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Seb\AuthenticatorBundle\Security\CredentialsCheckerInterface;
use Seb\AuthenticatorBundle\Security\CredentialsProviderInterface;
use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AuthenticatorInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class Authenticator implements AuthenticatorInterface
{
    use TargetPathTrait;

    private $credentialsProvider;
    private $credentialsChecker;
    private $missingUserPolicy;
    private $badCredentialsPolicy;
    private $successfulAuthenticationPolicy;
    private $authenticatedTokenProvider;

    public function __construct(
        CredentialsProviderInterface $credentialsProvider,
        CredentialsCheckerInterface $credentialsChecker,
        MissingUserPolicy $missingUserPolicy,
        BadCredentialsPolicy $badCredentialsPolicy,
        SuccessfulAuthenticationPolicy $successfulAuthenticationPolicy,
        AuthenticatedTokenProviderInterface $authenticatedTokenProvider
    ) {
        $this->credentialsProvider = $credentialsProvider;
        $this->credentialsChecker = $credentialsChecker;
        $this->missingUserPolicy = $missingUserPolicy;
        $this->badCredentialsPolicy = $badCredentialsPolicy;
        $this->successfulAuthenticationPolicy = $successfulAuthenticationPolicy;
        $this->authenticatedTokenProvider = $authenticatedTokenProvider;
    }

    public function supports(Request $request)
    {
        return $this->credentialsProvider->supports($request);
    }

    public function getCredentials(Request $request)
    {
        // Compatibility with older Symfony versions
        if (!$this->supports($request)) {
            return null;
        }

        return $this->credentialsProvider->getCredentials($request);
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $user = $userProvider->loadUserByUsername($credentials->getUsername());
        } catch (UsernameNotFoundException $exception) {
            $user = $this->missingUserPolicy->userNotFound($credentials);
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return $this->credentialsChecker->checkCredentials($credentials, $user);
    }

    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        $this->missingUserPolicy->successfulAuthentication($user);

        return $this->authenticatedTokenProvider->createAuthenticatedToken($user, $providerKey);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return $this->successfulAuthenticationPolicy->onAuthenticationSuccess($request, $token, $providerKey);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return $this->badCredentialsPolicy->onAuthenticationFailure($request, $exception);
    }

    public function supportsRememberMe()
    {
        return $this->credentialsProvider->supportsRememberMe();
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return $this->credentialsProvider->start($request, $authException);
    }
}
