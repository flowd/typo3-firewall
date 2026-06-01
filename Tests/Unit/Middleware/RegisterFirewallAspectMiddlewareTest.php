<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Middleware;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Typo3Firewall\Context\FirewallAspect;
use Flowd\Typo3Firewall\Middleware\RegisterFirewallAspectMiddleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class RegisterFirewallAspectMiddlewareTest extends TestCase
{
    public function testProcessAddsFirewallAspectToContext(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();
        $request
            ->expects($this->once())
            ->method('getAttribute')
            ->willReturn($requestContext);

        $middleware = new RegisterFirewallAspectMiddleware();
        $middleware->process(
            $request,
            new class implements RequestHandlerInterface {
                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return new Response();
                }
            }
        );

        self::assertInstanceOf(
            FirewallAspect::class,
            GeneralUtility::makeInstance(Context::class)
                ->getAspect('firewall')
        );
    }
}
