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

/**
 * @coversDefaultClass \Seb\AuthenticatorBundle\Security\CredentialsProviders\FormCredentialsProvider
 * @covers ::__construct
 */
class FormCredentialsProviderTest extends TestCase
{

    private $csrfTokenVerifier;
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
        $this->credentialsProvider = new FormCredentialsProvider($this->csrfTokenVerifier, $this->options);
    }

    /**
     * @covers ::supports
     */
    public function testSupportedRequest()
    {
        $request = Request::create($this->options['login_check_path'], 'POST');

        $this->assertTrue($this->credentialsProvider->supports($request),
            'The only supported request must be e POSt request to the login_check_path');
    }

    /**
     * @covers ::supports
     */
    public function testUnsupportedRequest()
    {
        $other_method = Request::create($this->options['login_check_path'], 'GET');
        $other_path = Request::create('/unsupported_path', 'POST');

        $this->assertFalse($this->credentialsProvider->supports($other_method),
            'The only supported request must be e POSt request to the login_check_path');
        $this->assertFalse($this->credentialsProvider->supports($other_path),
            'The only supported request must be e POSt request to the login_check_path');
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

        $response = $this->credentialsProvider->start($request);

        $this->assertEquals($redirectToLoginPage, $response);
    }

}
