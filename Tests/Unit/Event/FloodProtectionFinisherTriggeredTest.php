<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Event;

use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(FloodProtectionFinisherTriggered::class)]
final class FloodProtectionFinisherTriggeredTest extends TestCase
{
    #[Test]
    public function exposesTheRuleIdentifierPassedToTheConstructor(): void
    {
        $floodProtectionFinisherTriggered = new FloodProtectionFinisherTriggered('form-flood');

        self::assertSame('form-flood', $floodProtectionFinisherTriggered->ruleIdentifier);
    }

    #[Test]
    public function ruleIdentifierIsMutableSoListenersCanOverrideIt(): void
    {
        $floodProtectionFinisherTriggered = new FloodProtectionFinisherTriggered('form-flood');
        $floodProtectionFinisherTriggered->ruleIdentifier = 'custom-rule';

        self::assertSame('custom-rule', $floodProtectionFinisherTriggered->ruleIdentifier);
    }
}
