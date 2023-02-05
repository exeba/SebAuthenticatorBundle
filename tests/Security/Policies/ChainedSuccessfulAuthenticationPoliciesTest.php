<?php

namespace Seb\AuthenticatorBundle\Tests\Security\Policies;

use PHPUnit\Framework\TestCase;
use Seb\AuthenticatorBundle\Security\Policies\ChainedSuccessfulAuthenticationPolicies;
use Seb\AuthenticatorBundle\Security\SuccessfulAuthenticationPolicy;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class ChainedSuccessfulAuthenticationPoliciesTest extends TestCase
{
    private $firstMockPolicy;
    private $secondMockPolicy;

    private $testRequest;
    private $testTokenInterface;
    private $testProvider;

    private $chainedPolicy;

    /**
     * @covers ::__construct
     */
    protected function setUp(): void
    {
        $this->firstMockPolicy = $this->createMock(SuccessfulAuthenticationPolicy::class);
        $this->secondMockPolicy = $this->createMock(SuccessfulAuthenticationPolicy::class);

        $this->testRequest = new Request();
        $this->testTokenInterface = $this->createMock(TokenInterface::class);
        $this->testProvider = 'test-provider';

        $this->chainedPolicy = new ChainedSuccessfulAuthenticationPolicies($this->firstMockPolicy, $this->secondMockPolicy);
    }

    /**
     * @covers ::onAuthenticationSuccess
     */
    public function testNullWhenAllNulls()
    {
        $this->firstMockPolicy->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->testRequest, $this->testTokenInterface, $this->testProvider)
            ->willReturn(null);

        $this->secondMockPolicy->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->testRequest, $this->testTokenInterface, $this->testProvider)
            ->willReturn(null);

        $response = $this->chainedPolicy->onAuthenticationSuccess($this->testRequest, $this->testTokenInterface, $this->testProvider);

        $this->assertNull($response);
    }

    /**
     * @covers ::onAuthenticationSuccess
     */
    public function testFirstNotNull()
    {
        $expectedResponse = $this->createMock(Response::class);

        $this->firstMockPolicy->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->testRequest, $this->testTokenInterface, $this->testProvider)
            ->willReturn(null);

        $this->secondMockPolicy->method('onAuthenticationSuccess')
            ->with($this->testRequest, $this->testTokenInterface, $this->testProvider)
            ->willReturn($expectedResponse);

        $response = $this->chainedPolicy->onAuthenticationSuccess($this->testRequest, $this->testTokenInterface, $this->testProvider);

        $this->assertSame($expectedResponse, $response);
    }

    /**
     * @covers ::onAuthenticationSuccess
     */
    public function testStopAfterFirstNotNull()
    {
        $expectedResponse = $this->createMock(Response::class);

        $this->firstMockPolicy->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->testRequest, $this->testTokenInterface, $this->testProvider)
            ->willReturn($expectedResponse);

        $this->secondMockPolicy->expects($this->never())
            ->method('onAuthenticationSuccess');

        $response = $this->chainedPolicy->onAuthenticationSuccess($this->testRequest, $this->testTokenInterface, $this->testProvider);

        $this->assertSame($expectedResponse, $response);
    }
}
