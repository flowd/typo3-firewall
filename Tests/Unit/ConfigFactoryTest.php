<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Typo3Firewall\ConfigFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConfigFactory::class)]
final class ConfigFactoryTest extends TestCase
{
    #[Test]
    public function getConfigurationPathReturnsPhpFilePath(): void
    {
        $path = ConfigFactory::getConfigurationPath();

        self::assertStringEndsWith('/system/phirewall.php', $path);
    }

    #[Test]
    public function getPatternsFilePathReturnsJsonFilePath(): void
    {
        $path = ConfigFactory::getPatternsFilePath();

        self::assertStringEndsWith('/system/phirewall.patterns.json', $path);
    }

    #[Test]
    public function getBaseConfigPathReturnsValidPath(): void
    {
        $path = ConfigFactory::getBaseConfigPath();

        self::assertNotEmpty($path);
    }

    #[Test]
    public function configurationAndPatternsPathsShareSameBaseDirectory(): void
    {
        $configPath = ConfigFactory::getConfigurationPath();
        $patternsPath = ConfigFactory::getPatternsFilePath();

        self::assertSame(dirname($configPath), dirname($patternsPath));
    }
}
