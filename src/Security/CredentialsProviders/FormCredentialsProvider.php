<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsProviders;

use Seb\AuthenticatorBundle\Security\CredentialsProviderInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class FormCredentialsProvider implements CredentialsProviderInterface
{
    private $csrfTokenManager;
    private $options = [
        'username_parameter' => '_username',
        'password_parameter' => '_password',
        'csrf_parameter' => '_csrf_token',
        'login_path' => '/login',
        'login_check_path' => '/login_check',
    ];

    public function __construct(CsrfTokenManagerInterface $csrfTokenManager, $options)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->options = array_merge($this->options, $options);
    }

    public function supports(Request $request)
    {
        return $this->options['login_check_path'] === $request->getPathInfo() && $request->isMethod('POST');
    }

    public function getCredentials(Request $request)
    {
        $credentials = [
            'username' => $request->request->get($this->options['username_parameter']),
            'password' => $request->request->get($this->options['password_parameter']),
        ];

        $this->validateCsrfToken($request->request->get($this->options['csrf_parameter']));

        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials['username']
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
        return new RedirectResponse($this->options['login_path']);
    }
}
