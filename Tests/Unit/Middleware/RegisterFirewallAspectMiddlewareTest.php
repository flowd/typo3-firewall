<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Middleware;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Typo3Firewall\Context\FirewallAspect;
use Flowd\Typo3Firewall\Middleware\RegisterFirewallAspectMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\CMS\Core\Http\ServerRequest;

#[CoversClass(RegisterFirewallAspectMiddleware::class)]
final class RegisterFirewallAspectMiddlewareTest extends TestCase
{
    #[Test]
    public function processRegistersTheFirewallAspect(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $serverRequest = (new ServerRequest('https://example.com/'))
            ->withAttribute(RequestContext::ATTRIBUTE_NAME, $requestContext);
        $context = new Context();

        $response = (new RegisterFirewallAspectMiddleware($context))->process($serverRequest, $this->handler());

        $firewallAspect = $context->getAspect('firewall');
        self::assertInstanceOf(FirewallAspect::class, $firewallAspect);
        self::assertSame($requestContext, $firewallAspect->get('context'));
        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function processSkipsTheAspectWhenTheFirewallMiddlewareDidNotRun(): void
    {
        $context = new Context();

        $response = (new RegisterFirewallAspectMiddleware($context))
            ->process(new ServerRequest('https://example.com/'), $this->handler());

        self::assertFalse($context->hasAspect('firewall'));
        self::assertSame(200, $response->getStatusCode());
    }

    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response();
            }
        };
    }
}
