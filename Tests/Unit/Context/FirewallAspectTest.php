<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Context;

use Flowd\Phirewall\BanType;
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
        $firewallResult = FirewallResult::blocked('sqli', 'owasp');
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
    public function recordFailureDelegatesToTheRequestContext(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        $firewallAspect->recordFailure('form-flood', '10.0.0.7');

        self::assertTrue($requestContext->hasRecordedSignals());
        $recordedSignals = $requestContext->getRecordedSignals();
        self::assertCount(1, $recordedSignals);
        self::assertSame('form-flood', $recordedSignals[0]->ruleName);
        self::assertSame(BanType::Fail2Ban, $recordedSignals[0]->banType);
        self::assertSame('10.0.0.7', $recordedSignals[0]->key);
    }

    #[Test]
    public function recordFailureWithoutKeyLeavesTheKeyResolutionToTheFirewall(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        $firewallAspect->recordFailure('login-failures');

        self::assertNull($requestContext->getRecordedSignals()[0]->key);
    }

    #[Test]
    public function recordHitDelegatesToTheRequestContext(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        $firewallAspect->recordHit('expensive-operation', '10.0.0.7');

        $recordedSignals = $requestContext->getRecordedSignals();
        self::assertCount(1, $recordedSignals);
        self::assertSame('expensive-operation', $recordedSignals[0]->ruleName);
        self::assertSame(BanType::Allow2Ban, $recordedSignals[0]->banType);
        self::assertSame('10.0.0.7', $recordedSignals[0]->key);
    }

    #[Test]
    public function recordHitWithoutKeyLeavesTheKeyResolutionToTheFirewall(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());
        $firewallAspect = new FirewallAspect($requestContext);

        $firewallAspect->recordHit('expensive-operation');

        self::assertNull($requestContext->getRecordedSignals()[0]->key);
    }
}
