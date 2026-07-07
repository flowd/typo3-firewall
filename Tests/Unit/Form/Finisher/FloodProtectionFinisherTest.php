<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Form\Finisher;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;
use Flowd\Typo3Firewall\Form\Finisher\FloodProtectionFinisher;
use Flowd\Typo3Firewall\Form\FormFloodSettings;
use Flowd\Typo3Firewall\Tests\Unit\Fixtures\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Extbase\Mvc\ExtbaseRequestParameters;
use TYPO3\CMS\Extbase\Mvc\Request;
use TYPO3\CMS\Form\Domain\Finishers\FinisherContext;

#[CoversClass(FloodProtectionFinisher::class)]
#[UsesClass(FloodProtectionFinisherTriggered::class)]
final class FloodProtectionFinisherTest extends TestCase
{
    #[Test]
    public function recordsTheSubmissionForTheDefaultRule(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->execute($recordingEventDispatcher, $requestContext);

        self::assertSame(1, $recordingEventDispatcher->dispatchCount);
        self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $recordingEventDispatcher->lastEvent);

        $recordedSignals = $requestContext->getRecordedSignals();
        self::assertCount(1, $recordedSignals);
        self::assertSame(FormFloodSettings::DEFAULT_RULE_IDENTIFIER, $recordedSignals[0]->ruleName);
        self::assertSame(BanType::Allow2Ban, $recordedSignals[0]->banType);
        self::assertNull($recordedSignals[0]->key);
    }

    #[Test]
    public function recordsAgainstTheRuleIdentifierFromTheFinisherOption(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->execute($recordingEventDispatcher, $requestContext, ['ruleIdentifier' => 'contact-form-flood']);

        self::assertSame('contact-form-flood', $requestContext->getRecordedSignals()[0]->ruleName);
    }

    #[Test]
    public function blankRuleIdentifierOptionFallsBackToTheDefaultRule(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->execute($recordingEventDispatcher, $requestContext, ['ruleIdentifier' => '   ']);

        self::assertSame(FormFloodSettings::DEFAULT_RULE_IDENTIFIER, $requestContext->getRecordedSignals()[0]->ruleName);
    }

    #[Test]
    public function withoutFirewallRequestContextNothingIsDispatchedOrRecorded(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();

        $this->execute($recordingEventDispatcher, null);

        self::assertSame(0, $recordingEventDispatcher->dispatchCount);
    }

    #[Test]
    public function listenerCanOverrideTheRuleIdentifier(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();
        $recordingEventDispatcher->mutator = static function (object $event): void {
            self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $event);
            $event->ruleIdentifier = 'contact-form-flood';
        };
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->execute($recordingEventDispatcher, $requestContext);

        self::assertSame('contact-form-flood', $requestContext->getRecordedSignals()[0]->ruleName);
    }

    #[Test]
    public function listenerCanSkipTheSubmissionWithABlankRuleIdentifier(): void
    {
        $recordingEventDispatcher = new RecordingEventDispatcher();
        $recordingEventDispatcher->mutator = static function (object $event): void {
            self::assertInstanceOf(FloodProtectionFinisherTriggered::class, $event);
            $event->ruleIdentifier = '   ';
        };
        $requestContext = new RequestContext(FirewallResult::pass());

        $this->execute($recordingEventDispatcher, $requestContext);

        self::assertSame(1, $recordingEventDispatcher->dispatchCount);
        self::assertFalse($requestContext->hasRecordedSignals());
    }

    /**
     * @param array<string, mixed> $options
     */
    private function execute(RecordingEventDispatcher $recordingEventDispatcher, ?RequestContext $requestContext, array $options = []): void
    {
        $serverRequest = (new ServerRequest('https://example.com/'))
            ->withAttribute('extbase', new ExtbaseRequestParameters());

        if ($requestContext instanceof RequestContext) {
            $serverRequest = $serverRequest->withAttribute(RequestContext::ATTRIBUTE_NAME, $requestContext);
        }

        $finisherContext = $this->createMock(FinisherContext::class);
        $finisherContext->method('getRequest')->willReturn(new Request($serverRequest));

        $floodProtectionFinisher = new FloodProtectionFinisher($recordingEventDispatcher);
        $floodProtectionFinisher->setOptions($options);
        $floodProtectionFinisher->execute($finisherContext);
    }
}
