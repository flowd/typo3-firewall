<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Configuration;

use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Flowd\Typo3Firewall\Configuration\FormFloodingProtection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ExtensionConfiguration::class)]
#[UsesClass(FormFloodingProtection::class)]
final class ExtensionConfigurationTest extends TestCase
{
    #[Test]
    public function emptySettingYieldsDisabledFloodingWithDefaults(): void
    {
        $flooding = (new ExtensionConfiguration([]))->formFloodingProtection;

        self::assertFalse($flooding->enabled);
        self::assertSame(5, $flooding->threshold);
        self::assertSame(60, $flooding->period);
        self::assertSame(3600, $flooding->ban);
    }

    #[Test]
    public function missingFloodingSectionYieldsDefaults(): void
    {
        $flooding = (new ExtensionConfiguration(['form' => []]))->formFloodingProtection;

        self::assertFalse($flooding->enabled);
        self::assertSame(5, $flooding->threshold);
    }

    #[Test]
    public function emptyFloodingSectionYieldsDefaults(): void
    {
        $flooding = (new ExtensionConfiguration(['form' => ['flooding' => []]]))->formFloodingProtection;

        self::assertFalse($flooding->enabled);
        self::assertSame(5, $flooding->threshold);
    }

    #[Test]
    public function readsTypedValues(): void
    {
        $flooding = (new ExtensionConfiguration([
            'form' => ['flooding' => ['enable' => true, 'threshold' => 7, 'period' => 120, 'ban' => 600]],
        ]))->formFloodingProtection;

        self::assertTrue($flooding->enabled);
        self::assertSame(7, $flooding->threshold);
        self::assertSame(120, $flooding->period);
        self::assertSame(600, $flooding->ban);
    }

    #[Test]
    public function coercesStringValuesAsDeliveredByTypo3ExtensionConfiguration(): void
    {
        // TYPO3's ExtensionConfiguration->get() returns dotted keys as strings ('0'/'1'/'5').
        $flooding = (new ExtensionConfiguration([
            'form' => ['flooding' => ['enable' => '1', 'threshold' => '7', 'period' => '120', 'ban' => '600']],
        ]))->formFloodingProtection;

        self::assertTrue($flooding->enabled);
        self::assertSame(7, $flooding->threshold);
        self::assertSame(120, $flooding->period);
        self::assertSame(600, $flooding->ban);
    }

    #[Test]
    public function disabledFlagStringZeroIsFalse(): void
    {
        $flooding = (new ExtensionConfiguration(['form' => ['flooding' => ['enable' => '0']]]))->formFloodingProtection;

        self::assertFalse($flooding->enabled);
    }

    #[Test]
    public function nonNumericValuesFallBackToDefaults(): void
    {
        $flooding = (new ExtensionConfiguration([
            'form' => ['flooding' => ['enable' => '1', 'threshold' => 'not-a-number']],
        ]))->formFloodingProtection;

        self::assertTrue($flooding->enabled);
        self::assertSame(5, $flooding->threshold);
    }
}
