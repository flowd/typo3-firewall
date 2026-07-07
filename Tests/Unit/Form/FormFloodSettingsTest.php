<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Form;

use Flowd\Typo3Firewall\Form\FormFloodSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

#[CoversClass(FormFloodSettings::class)]
final class FormFloodSettingsTest extends TestCase
{
    #[Test]
    public function protectionIsDisabledByDefault(): void
    {
        self::assertFalse($this->createSettings([])->isEnabled());
    }

    #[Test]
    public function protectionCanBeEnabled(): void
    {
        self::assertTrue($this->createSettings(['formFloodEnabled' => '1'])->isEnabled());
    }

    #[Test]
    public function thresholdPeriodAndBanFallbackToTheirDefaults(): void
    {
        $formFloodSettings = $this->createSettings([]);

        self::assertSame(5, $formFloodSettings->getThreshold());
        self::assertSame(60, $formFloodSettings->getPeriod());
        self::assertSame(3600, $formFloodSettings->getBanSeconds());
    }

    #[Test]
    public function configuredValuesAreUsed(): void
    {
        $formFloodSettings = $this->createSettings([
            'formFloodThreshold' => '7',
            'formFloodPeriod' => '120',
            'formFloodBan' => '600',
        ]);

        self::assertSame(7, $formFloodSettings->getThreshold());
        self::assertSame(120, $formFloodSettings->getPeriod());
        self::assertSame(600, $formFloodSettings->getBanSeconds());
    }

    #[Test]
    public function valuesNeverGoBelowOne(): void
    {
        $formFloodSettings = $this->createSettings([
            'formFloodThreshold' => '0',
            'formFloodPeriod' => '-5',
            'formFloodBan' => 'not-a-number',
        ]);

        self::assertSame(1, $formFloodSettings->getThreshold());
        self::assertSame(1, $formFloodSettings->getPeriod());
        self::assertSame(1, $formFloodSettings->getBanSeconds());
    }

    /**
     * @param array<string, string> $settings
     */
    private function createSettings(array $settings): FormFloodSettings
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($settings): string {
                self::assertSame('firewall', $extension);
                if (!isset($settings[$path])) {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000002);
                }

                return $settings[$path];
            }
        );

        return new FormFloodSettings($extensionConfiguration);
    }
}
