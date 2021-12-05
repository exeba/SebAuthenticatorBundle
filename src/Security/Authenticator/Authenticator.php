<?php

namespace Seb\AuthenticatorBundle\Security\Authenticator;

use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Seb\AuthenticatorBundle\Security\CredentialsProviderInterface;
use Seb\AuthenticatorBundle\Security\PassportProviderInterface;
use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class Authenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{

    private $credentialsProvider;
    private $passportProvider;
    private $authenticatedTokenProvider;
    private $successfulAuthenticationPolicy;
    private $badCredentialsPolicy;

    public function __construct(
        CredentialsProviderInterface        $credentialsProvider,
        PassportProviderInterface           $passportProvider,
        AuthenticatedTokenProviderInterface $authenticatedTokenProvider,
        SuccessfulAuthenticationPolicy      $successfulAuthenticationPolicy,
        BadCredentialsPolicy                $badCredentialsPolicy)
    {
        $this->credentialsProvider = $credentialsProvider;
        $this->passportProvider = $passportProvider;
        $this->authenticatedTokenProvider = $authenticatedTokenProvider;
        $this->successfulAuthenticationPolicy = $successfulAuthenticationPolicy;
        $this->badCredentialsPolicy = $badCredentialsPolicy;
    }

    public function supports(Request $request): ?bool
    {
        return $this->credentialsProvider->supports($request);
    }

    public function authenticate(Request $request): Passport
    {
        $credentials = $this->credentialsProvider->getCredentials($request);
        $passport = $this->passportProvider->authenticate($credentials);
        if ($this->credentialsProvider->supportsRememberMe()) {
            $passport->addBadge(new RememberMeBadge());
        }

        return $passport;
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if ($passport instanceof Passport) {
            return $this->createToken($passport, $firewallName);
        }

        throw new AuthenticationException('Unsupported passport class: '.get_class($passport));
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return $this->authenticatedTokenProvider->createAuthenticatedToken($passport, $firewallName);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->successfulAuthenticationPolicy->onAuthenticationSuccess($request, $token, $firewallName);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->badCredentialsPolicy->onAuthenticationFailure($request, $exception);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $this->credentialsProvider->start($request, $authException);
    }
}
