<?php


namespace Seb\AuthenticatorBundle\Tests\Security\Guard;


use PHPUnit\Framework\TestCase;
use Seb\AuthenticatorBundle\Security\AuthenticatedTokenProviderInterface;
use Seb\AuthenticatorBundle\Security\BadCredentialsPolicy;
use Seb\AuthenticatorBundle\Security\CredentialsCheckerInterface;
use Seb\AuthenticatorBundle\Security\CredentialsProviderInterface;
use Seb\AuthenticatorBundle\Security\Guard\Authenticator;
use Seb\AuthenticatorBundle\Security\MissingUserPolicy;
use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Seb\AuthenticatorBundle\Tests\Security\Dummy\DummyCredentials;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;

/**
 * @coversDefaultClass \Seb\AuthenticatorBundle\Security\Guard\Authenticator
 * @covers ::__construct
 */
class AuthenticatorTest extends TestCase
{
    private $credentialsProvider;
    private $credentialsChecker;
    private $missingUserPolicy;
    private $badCredentialsPolicy;
    private $succesfulAuthenticationPolicy;
    private $tokenProvider;

    private $authenticator;


    public function setUp(): void
    {
        $this->credentialsProvider = $this->createMock(CredentialsProviderInterface::class);
        $this->credentialsChecker = $this->createMock(CredentialsCheckerInterface::class);
        $this->missingUserPolicy = $this->createMock(MissingUserPolicy::class);
        $this->badCredentialsPolicy = $this->createMock(BadCredentialsPolicy::class);
        $this->succesfulAuthenticationPolicy = $this->createMock(SuccessfulAuthenticationPolicy::class);
        $this->tokenProvider = $this->createMock(AuthenticatedTokenProviderInterface::class);

        $this->authenticator = new Authenticator(
            $this->credentialsProvider,
            $this->credentialsChecker,
            $this->missingUserPolicy,
            $this->badCredentialsPolicy,
            $this->succesfulAuthenticationPolicy,
            $this->tokenProvider
        );
    }

    /**
     * @covers ::start
     */
    public function testStart()
    {
        $request = Request::create('/hello-world', 'GET');
        $exception = new AuthenticationException("Exception!");

        // 'start' method should simply forward che call
        $this->credentialsProvider
            ->expects($this->once())
            ->method('start')
            ->with($request, $exception);

        $this->authenticator->start($request, $exception);
    }

    /**
     * @covers ::supports
     */
    public function testSupports()
    {
        $supportedRequest = Request::create('/supported');
        $unsupportedRequest = Request::create('/unsupported');

        $this->credentialsProvider->method('supports')
                ->will($this->returnValueMap([
                    [$supportedRequest, true],
                    [$unsupportedRequest, false],
                ]));

        $this->assertTrue($this->authenticator->supports($supportedRequest));
        $this->assertFalse($this->authenticator->supports($unsupportedRequest));
    }

    /**
     * @covers ::getCredentials
     * @covers ::supports
     */
    public function testGetCredentialsUnsupportedRequest()
    {
        $this->credentialsProvider->method('supports')
                ->willReturn(false);

        $this->assertNull($this->authenticator->getCredentials(Request::create('/unsupported')),
            'getCredentials must return null when the request is not supported');
    }

    /**
     * @covers ::getCredentials
     * @covers ::supports
     */
    public function testGetCredentialsSupportedRequest()
    {
        $supportedRequest = Request::create('/supported');
        $dummyCredentials = new DummyCredentials('user');

        $this->credentialsProvider->method('supports')
                ->willReturn(true);
        $this->credentialsProvider->method('getCredentials')
                ->with($supportedRequest)->willReturn($dummyCredentials);

        $this->assertSame($dummyCredentials, $this->authenticator->getCredentials($supportedRequest),
            'getCredentials must forward the call to credentials provider when the request is supported');
    }

    /**
     * @covers ::supportsRememberMe
     */
    public function testSupportsRememberMe()
    {
        $this->credentialsProvider->method('supportsRememberMe')
                ->will($this->onConsecutiveCalls(true, false));

        $this->assertTrue($this->authenticator->supportsRememberMe(),
            'supportsRememberMe must forward the call to credentials provider');
        $this->assertFalse($this->authenticator->supportsRememberMe(),
            'supportsRememberMe must forward the call to credentials provider');
    }

    /**
     * @covers ::getUser
     */
    public function testGetExistingUser()
    {
        $credentials = $dummyCredentials = new DummyCredentials('existingUser');
        $expectedUser = $this->createMock(UserInterface::class);

        $userProvider = $this->createMock(UserProviderInterface::class);
        $userProvider->method('loadUserByUsername')->with($credentials->getUsername())->willReturn($expectedUser);

        $actualUser = $this->authenticator->getUser($credentials, $userProvider);
        $this->assertSame($expectedUser, $actualUser);
    }

    /**
     * @covers ::getUser
     */
    public function testGetCreatedUser()
    {
        $credentials = $dummyCredentials = new DummyCredentials('existingUser');
        $expectedUser = $this->createMock(UserInterface::class);

        $userProvider = $this->createMock(UserProviderInterface::class);
        $userProvider->method('loadUserByUsername')
                ->with($credentials->getUsername())
                ->willThrowException(new UsernameNotFoundException());

        $this->missingUserPolicy->method('userNotFound')
                ->with($credentials)
                ->willReturn($expectedUser);

        $actualUser = $this->authenticator->getUser($credentials, $userProvider);
        $this->assertSame($expectedUser, $actualUser);
    }

    /**
     * @covers ::getUser
     */
    public function testGetMissingUser()
    {
        $credentials = $dummyCredentials = new DummyCredentials('missingUser');

        $userProvider = $this->createMock(UserProviderInterface::class);
        $userProvider->method('loadUserByUsername')
            ->with($credentials->getUsername())
            ->willThrowException(new UsernameNotFoundException());

        $this->missingUserPolicy->method('userNotFound')
            ->with($credentials)
            ->willThrowException(new UsernameNotFoundException("really not found"));

        $this->expectException(UsernameNotFoundException::class);
        $this->authenticator->getUser($credentials, $userProvider);
    }

    /**
     * @covers ::checkCredentials
     */
    public function testCheckCredentials()
    {
        $credentials = $dummyCredentials = new DummyCredentials('username');
        $user = $this->createMock(UserInterface::class);

        $this->credentialsChecker->expects($this->once())
                ->method('checkCredentials')
                ->with($credentials, $user);

        $this->authenticator->checkCredentials($credentials, $user);
    }

    /**
     * @covers ::createAuthenticatedToken
     */
    public function testCreateAuthenticatedToken()
    {
        $providerKey = 'providerKey';
        $roles = [ 'role1', 'role2' ];
        $user = $this->createMock(UserInterface::class);
        $user->method('getRoles')->willReturn($roles);


        $expectedToken = new PostAuthenticationGuardToken($user, $providerKey, $roles);
        $this->tokenProvider->expects($this->once())
                ->method('createAuthenticatedToken')
                ->with($user, $providerKey)
                ->willReturn($expectedToken);
        $this->missingUserPolicy->expects($this->once())
                ->method('successfulAuthentication')
                ->with($user);

        $actualToken = $this->authenticator->createAuthenticatedToken($user, $providerKey);
        $this->assertEquals($expectedToken, $actualToken);
    }

    /**
     * @covers ::onAuthenticationSuccess
     */
    public function testOnAuthenticationSuccess()
    {
        $request = Request::create('/dummy_path');
        $token = $this->createMock(TokenInterface::class);
        $provider = 'dummy_provider';

        $this->succesfulAuthenticationPolicy->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($request, $token, $provider);

        $this->authenticator->onAuthenticationSuccess($request, $token, $provider);
    }

    /**
     * @covers ::onAuthenticationFailure
     */
    public function testOnAuthenticationFailure()
    {
        $request = Request::create('/dummy_path');
        $exception = new AuthenticationException("dummy exception");

        $this->badCredentialsPolicy->expects($this->once())
                ->method('onAuthenticationFailure')
                ->with($request, $exception);

        $this->authenticator->onAuthenticationFailure($request, $exception);
    }

}
