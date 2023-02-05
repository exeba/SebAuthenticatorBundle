<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsProviders;

use Seb\AuthenticatorBundle\Security\CredentialsProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\HttpUtils;

class FormCredentialsProvider implements CredentialsProviderInterface
{
    private $csrfTokenManager;
    private $httpUtils;
    private $options = [
        'username_parameter' => '_username',
        'password_parameter' => '_password',
        'csrf_parameter' => '_csrf_token',
        'login_path' => '/login',
        'login_check_path' => '/login_check',
    ];

    public function __construct(
        CsrfTokenManagerInterface $csrfTokenManager,
        HttpUtils $httpUtils,
        $options)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->httpUtils = $httpUtils;
        $this->options = array_merge($this->options, $options);
    }

    public function supports(Request $request)
    {
        if ($request->isMethod('POST')) {
            return $this->httpUtils->checkRequestPath($request, $this->options['login_check_path']);
        }

        return false;
    }

    public function getCredentials(Request $request)
    {
        $credentials = new FormCredentials(
            $request->request->get($this->options['username_parameter']),
            $request->request->get($this->options['password_parameter'])
        );

        $this->validateCsrfToken($request->request->get($this->options['csrf_parameter']));

        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials->getUsername()
        );

        return $credentials;
    }

    private function validateCsrfToken($csrfTokenValue)
    {
        $token = new CsrfToken('authenticate', $csrfTokenValue);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }
    }

    public function supportsRememberMe()
    {
        return true;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return $this->httpUtils->createRedirectResponse($request, $this->options['login_path']);
    }
}
