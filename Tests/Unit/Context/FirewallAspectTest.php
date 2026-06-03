<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Context;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Typo3Firewall\Context\FirewallAspect;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Context\Exception\AspectPropertyNotFoundException;

#[CoversClass(FirewallAspect::class)]
final class FirewallAspectTest extends TestCase
{
    #[Test]
    public function getContextReturnsTheWrappedRequestContext(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        self::assertSame($requestContext, $firewallAspect->get('context'));
    }

    #[Test]
    public function getResultReturnsTheRequestContextResult(): void
    {
        $firewallResult = FirewallResult::blocked('owasp', 'sqli');
        $firewallAspect = new FirewallAspect(new RequestContext($firewallResult));

        self::assertSame($firewallResult, $firewallAspect->get('result'));
    }

    #[Test]
    public function getUnknownPropertyThrows(): void
    {
        $firewallAspect = new FirewallAspect(new RequestContext(FirewallResult::pass()));

        $this->expectException(AspectPropertyNotFoundException::class);
        $this->expectExceptionCode(1780065304);

        $firewallAspect->get('does-not-exist');
    }

    #[Test]
    public function recordFailureDelegatesToRequestContext(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        $firewallAspect->recordFailure('form-flood', '10.0.0.7');

        self::assertTrue($requestContext->hasRecordedSignals());
        $failures = $requestContext->getRecordedFailures();
        self::assertCount(1, $failures);
        self::assertSame('form-flood', $failures[0]->ruleName);
        self::assertSame('10.0.0.7', $failures[0]->key);
    }
}
