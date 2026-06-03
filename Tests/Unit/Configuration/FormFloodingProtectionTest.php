<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Configuration;

use Flowd\Typo3Firewall\Configuration\FormFloodingProtection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(FormFloodingProtection::class)]
final class FormFloodingProtectionTest extends TestCase
{
    #[Test]
    public function constructorDefaultsAreOptInWithSensibleLimits(): void
    {
        $formFloodingProtection = new FormFloodingProtection();

        self::assertFalse($formFloodingProtection->enabled);
        self::assertSame(5, $formFloodingProtection->threshold);
        self::assertSame(60, $formFloodingProtection->period);
        self::assertSame(3600, $formFloodingProtection->ban);
    }

    #[Test]
    public function tryFromEmptyArrayReturnsDefaults(): void
    {
        $formFloodingProtection = FormFloodingProtection::tryFrom([]);

        self::assertEquals(new FormFloodingProtection(), $formFloodingProtection);
    }

    #[Test]
    public function tryFromReadsTypedValues(): void
    {
        $formFloodingProtection = FormFloodingProtection::tryFrom([
            'enable' => true,
            'threshold' => 7,
            'period' => 120,
            'ban' => 600,
        ]);

        self::assertTrue($formFloodingProtection->enabled);
        self::assertSame(7, $formFloodingProtection->threshold);
        self::assertSame(120, $formFloodingProtection->period);
        self::assertSame(600, $formFloodingProtection->ban);
    }

    #[Test]
    public function tryFromCoercesNumericStringsAsDeliveredByTypo3(): void
    {
        // TYPO3 ExtensionConfiguration->get() returns dotted keys as strings.
        $formFloodingProtection = FormFloodingProtection::tryFrom([
            'enable' => '1',
            'threshold' => '7',
            'period' => '120',
            'ban' => '600',
        ]);

        self::assertTrue($formFloodingProtection->enabled);
        self::assertSame(7, $formFloodingProtection->threshold);
        self::assertSame(120, $formFloodingProtection->period);
        self::assertSame(600, $formFloodingProtection->ban);
    }

    #[Test]
    public function tryFromTreatsStringZeroEnableAsDisabled(): void
    {
        // (bool)(int)'0' === false — important for the string-typed TYPO3 input.
        $formFloodingProtection = FormFloodingProtection::tryFrom(['enable' => '0']);

        self::assertFalse($formFloodingProtection->enabled);
    }

    #[Test]
    public function tryFromKeepsDefaultsForNonNumericValues(): void
    {
        $formFloodingProtection = FormFloodingProtection::tryFrom([
            'threshold' => 'not-a-number',
            'period' => '',
            'ban' => 'soon',
        ]);

        self::assertSame(5, $formFloodingProtection->threshold);
        self::assertSame(60, $formFloodingProtection->period);
        self::assertSame(3600, $formFloodingProtection->ban);
    }

    #[Test]
    public function tryFromAppliesEnableWithoutOtherValues(): void
    {
        $formFloodingProtection = FormFloodingProtection::tryFrom(['enable' => '1']);

        self::assertTrue($formFloodingProtection->enabled);
        self::assertSame(5, $formFloodingProtection->threshold);
        self::assertSame(60, $formFloodingProtection->period);
        self::assertSame(3600, $formFloodingProtection->ban);
    }
}
