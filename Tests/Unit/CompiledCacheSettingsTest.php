<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Typo3Firewall\CompiledCacheSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;

#[CoversClass(CompiledCacheSettings::class)]
final class CompiledCacheSettingsTest extends TestCase
{
    #[Test]
    public function enabledByDefaultWhenTheSettingIsAbsent(): void
    {
        self::assertTrue($this->createSettings([])->isEnabled());
    }

    #[Test]
    public function canBeDisabled(): void
    {
        self::assertFalse($this->createSettings(['compiledCacheEnabled' => '0'])->isEnabled());
    }

    #[Test]
    public function fallsBackToTheVarCodeCacheDirectory(): void
    {
        $directory = $this->createSettings([])->getDirectory();

        self::assertSame(Environment::getVarPath() . '/cache/code/firewall', $directory);
    }

    #[Test]
    public function aConfiguredDirectoryWins(): void
    {
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => '/srv/cache/phirewall']);

        self::assertSame('/srv/cache/phirewall', $compiledCacheSettings->getDirectory());
    }

    #[Test]
    public function aBlankConfiguredDirectoryFallsBack(): void
    {
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => '   ']);

        self::assertSame(Environment::getVarPath() . '/cache/code/firewall', $compiledCacheSettings->getDirectory());
    }

    /**
     * @param array<string, string> $settings
     */
    private function createSettings(array $settings): CompiledCacheSettings
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($settings): string {
                if (!isset($settings[$path])) {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000005);
                }

                return $settings[$path];
            }
        );

        return new CompiledCacheSettings($extensionConfiguration);
    }
}
