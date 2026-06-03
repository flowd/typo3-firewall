<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Form\Finisher;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;
use Flowd\Typo3Firewall\Form\Finisher\FloodProtectionFinisher;
use Flowd\Typo3Firewall\Tests\Unit\Fixtures\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Extbase\Mvc\ExtbaseRequestParameters;
use TYPO3\CMS\Extbase\Mvc\Request;
use TYPO3\CMS\Form\Domain\Finishers\AbstractFinisher;
use TYPO3\CMS\Form\Domain\Finishers\FinisherContext;

#[CoversClass(FloodProtectionFinisher::class)]
#[UsesClass(ExtensionConfiguration::class)]
#[UsesClass(FloodProtectionFinisherTriggered::class)]
final class FloodProtectionFinisherTest extends TestCase
{
    #[Test]
    public function disabledProtectionDispatchesNothingAndRecordsNothing(): void
    {
        $dispatcher = $this->dispatcher();
        $finisherContext = $this->createMock(FinisherContext::class);
        $finisherContext->expects(self::never())->method('getRequest');

        $this->executeInternal(
            new FloodProtectionFinisher($dispatcher, $this->extensionConfiguration(false)),
            $finisherContext,
        );

        self::assertSame(0, $dispatcher->dispatchCount);
    }

    #[Test]
    public function enabledRecordsFailureWithDefaultRuleAndResolvedClientIp(): void
    {
        $dispatcher = $this->dispatcher();
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->executeInternal(
            new FloodProtectionFinisher($dispatcher, $this->extensionConfiguration(true)),
            $this->finisherContext($this->request($requestContext)),
        );

        self::assertSame(1, $dispatcher->dispatchCount);
        self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $dispatcher->lastEvent);

        $failures = $requestContext->getRecordedFailures();
        self::assertCount(1, $failures);
        self::assertSame(FloodProtectionFinisher::DEFAULT_RULE_IDENTIFIER, $failures[0]->ruleName);
        self::assertSame('203.0.113.7', $failures[0]->key);
    }

    #[Test]
    public function withoutFirewallRequestContextNothingIsDispatchedOrRecorded(): void
    {
        $dispatcher = $this->dispatcher();

        $this->executeInternal(
            new FloodProtectionFinisher($dispatcher, $this->extensionConfiguration(true)),
            $this->finisherContext($this->request(null)),
        );

        self::assertSame(0, $dispatcher->dispatchCount);
    }

    #[Test]
    public function listenerCanOverrideTheRuleIdentifier(): void
    {
        $dispatcher = $this->dispatcher();
        $dispatcher->mutator = static function (object $event): void {
            self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $event);
            $event->ruleIdentifier = 'custom-rule';
        };
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->executeInternal(
            new FloodProtectionFinisher($dispatcher, $this->extensionConfiguration(true)),
            $this->finisherContext($this->request($requestContext)),
        );

        self::assertSame('custom-rule', $requestContext->getRecordedFailures()[0]->ruleName);
    }

    #[Test]
    public function blankRuleIdentifierFromListenerSkipsRecording(): void
    {
        $dispatcher = $this->dispatcher();
        $dispatcher->mutator = static function (object $event): void {
            self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $event);
            $event->ruleIdentifier = '   ';
        };
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->executeInternal(
            new FloodProtectionFinisher($dispatcher, $this->extensionConfiguration(true)),
            $this->finisherContext($this->request($requestContext)),
        );

        self::assertSame(1, $dispatcher->dispatchCount);
        self::assertFalse($requestContext->hasRecordedSignals());
    }

    #[Test]
    public function clientIpFallsBackToUnknownWithoutNormalizedParams(): void
    {
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->executeInternal(
            new FloodProtectionFinisher($this->dispatcher(), $this->extensionConfiguration(true)),
            $this->finisherContext($this->request($requestContext, withNormalizedParams: false)),
        );

        self::assertSame('unknown', $requestContext->getRecordedFailures()[0]->key);
    }

    private function dispatcher(): RecordingEventDispatcher
    {
        return new RecordingEventDispatcher();
    }

    private function extensionConfiguration(bool $enabled): ExtensionConfiguration
    {
        return new ExtensionConfiguration(['form' => ['flooding' => ['enable' => $enabled]]]);
    }

    private function request(?RequestContext $requestContext, bool $withNormalizedParams = true): Request
    {
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('extbase', new ExtbaseRequestParameters());

        if ($requestContext instanceof RequestContext) {
            $request = $request->withAttribute(RequestContext::ATTRIBUTE_NAME, $requestContext);
        }

        if ($withNormalizedParams) {
            $request = $request->withAttribute(
                'normalizedParams',
                NormalizedParams::createFromServerParams(['REMOTE_ADDR' => '203.0.113.7']),
            );
        }

        return new Request($request);
    }

    private function finisherContext(Request $request): FinisherContext
    {
        $finisherContext = $this->createMock(FinisherContext::class);
        $finisherContext->method('getRequest')->willReturn($request);

        return $finisherContext;
    }

    private function executeInternal(FloodProtectionFinisher $floodProtectionFinisher, FinisherContext $finisherContext): void
    {
        $reflectionProperty = new \ReflectionProperty(AbstractFinisher::class, 'finisherContext');
        $reflectionProperty->setValue($floodProtectionFinisher, $finisherContext);

        (new \ReflectionMethod($floodProtectionFinisher, 'executeInternal'))->invoke($floodProtectionFinisher);
    }
}
