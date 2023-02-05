<?php

namespace Seb\AuthenticatorBundle\Tests\Security\CredentialsProvider;

use PHPUnit\Framework\TestCase;
use Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentials;
use Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentialsProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * @coversDefaultClass \Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentialsProvider
 *
 * @covers ::__construct
 */
class FormCredentialsProviderTest extends TestCase
{
    private $csrfTokenVerifier;
    private $httpUtils;
    private $options = [
        'username_parameter' => '_username_test',
        'password_parameter' => '_password_test',
        'csrf_parameter' => '_csrf_token_test',
        'login_path' => '/login_test',
        'login_check_path' => '/login_check_test',
    ];

    private $credentialsProvider;

    /**
     * @covers ::__construct
     */
    public function setUp(): void
    {
        $this->csrfTokenVerifier = $this->createMock(CsrfTokenManagerInterface::class);
        $this->httpUtils = $this->createMock(HttpUtils::class);
        $this->credentialsProvider = new FormCredentialsProvider($this->csrfTokenVerifier, $this->httpUtils, $this->options);
    }

    /**
     * @covers ::supports
     */
    public function testSupportedRequest()
    {
        $request = Request::create('/supported_path', 'POST');

        $this->httpUtils->method('checkRequestPath')->with($request, $this->options['login_check_path'])
            ->willReturn(true);

        $this->assertTrue($this->credentialsProvider->supports($request),
            'The only supported request must be e POSt request to the login_check_path');
    }

    /**
     * @covers ::supports
     */
    public function testUnsupportedRequest()
    {
        $request = Request::create('/unsupported_path1', 'POST');

        $this->httpUtils->method('checkRequestPath')->with($request, $this->options['login_check_path'])
            ->willReturn(false);

        $this->assertFalse($this->credentialsProvider->supports($request),
            'The only supported request must be e POST request to the login_check_path');
    }

    /**
     * @covers ::getCredentials
     * @covers ::validateCsrfToken
     */
    public function testGetCredentialsWithValidToken()
    {
        $request = Request::create($this->options['login_check_path'], 'POST', [
            $this->options['username_parameter'] => 'test_user',
            $this->options['password_parameter'] => 'test_pass',
            $this->options['csrf_parameter'] => 'test_token',
        ]);
        $session = $this->createMock(SessionInterface::class);
        $request->setSession($session);

        $expectedCredentials = new FormCredentials('test_user', 'test_pass');

        $this->csrfTokenVerifier->method('isTokenValid')->willReturn(true);

        $actualCredentials = $this->credentialsProvider->getCredentials($request);

        $this->assertEquals($expectedCredentials, $actualCredentials);
    }

    /**
     * @covers ::getCredentials
     * @covers ::validateCsrfToken
     */
    public function testGetCredentialsWithInvalidToken()
    {
        $request = Request::create($this->options['login_check_path'], 'POST', [
            $this->options['username_parameter'] => 'test_user',
            $this->options['password_parameter'] => 'test_pass',
            $this->options['csrf_parameter'] => 'test_token',
        ]);

        $this->csrfTokenVerifier->method('isTokenValid')->willReturn(false);

        $this->expectException(InvalidCsrfTokenException::class);
        $this->credentialsProvider->getCredentials($request);
    }

    /**
     * @covers ::supportsRememberMe
     */
    public function testSupportsRememberMe()
    {
        $this->assertTrue($this->credentialsProvider->supportsRememberMe());
    }

    /**
     * @covers ::start
     */
    public function testStart()
    {
        $request = Request::create('/path');
        $redirectToLoginPage = new RedirectResponse($this->options['login_path']);

        $this->httpUtils->method('createRedirectResponse')
            ->with($request, $this->options['login_path'])
            ->willReturn($redirectToLoginPage);

        $response = $this->credentialsProvider->start($request);

        $this->assertEquals($redirectToLoginPage, $response);
    }
}
