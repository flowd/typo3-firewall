<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Pattern;

use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Pattern\PatternStorageSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;

#[CoversClass(PatternStorageSettings::class)]
final class PatternStorageSettingsTest extends TestCase
{
    #[Test]
    public function fallsBackToTheDirectoryOfTheConfigurationFile(): void
    {
        $patternsFilePath = $this->createSettings([])->getPatternsFilePath();

        self::assertStringEndsWith('/system/phirewall.patterns.json', $patternsFilePath);
        self::assertSame(dirname(ConfigFactory::getConfigurationPath()), dirname($patternsFilePath));
    }

    #[Test]
    public function aConfiguredDirectoryWithinTheProjectWins(): void
    {
        $directory = Environment::getProjectPath() . '/var/firewall-patterns';
        $patternStorageSettings = $this->createSettings(['patternsDirectory' => $directory]);

        self::assertSame($directory, $patternStorageSettings->getDirectory());
        self::assertSame($directory . '/phirewall.patterns.json', $patternStorageSettings->getPatternsFilePath());
    }

    #[Test]
    public function aTrailingSlashInTheConfiguredDirectoryIsIgnored(): void
    {
        $directory = Environment::getProjectPath() . '/var/firewall-patterns';
        $patternStorageSettings = $this->createSettings(['patternsDirectory' => $directory . '/']);

        self::assertSame($directory . '/phirewall.patterns.json', $patternStorageSettings->getPatternsFilePath());
    }

    #[Test]
    public function aBlankConfiguredDirectoryFallsBack(): void
    {
        $patternStorageSettings = $this->createSettings(['patternsDirectory' => '   ']);

        self::assertSame(dirname(ConfigFactory::getConfigurationPath()), $patternStorageSettings->getDirectory());
    }

    #[Test]
    public function aDirectoryOutsideTheAllowedPathsFallsBackAndWarns(): void
    {
        $logger = $this->createSpyLogger();
        $patternStorageSettings = $this->createSettings(['patternsDirectory' => '/srv/firewall'], $logger);

        self::assertSame(dirname(ConfigFactory::getConfigurationPath()), $patternStorageSettings->getDirectory());
        self::assertCount(1, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
    }

    #[Test]
    public function aPathTraversalInTheConfiguredDirectoryFallsBack(): void
    {
        $directory = Environment::getProjectPath() . '/var/../../outside';
        $patternStorageSettings = $this->createSettings(['patternsDirectory' => $directory]);

        self::assertSame(dirname(ConfigFactory::getConfigurationPath()), $patternStorageSettings->getDirectory());
    }

    /**
     * @param array<string, string> $settings
     */
    private function createSettings(array $settings, ?LoggerInterface $logger = null): PatternStorageSettings
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($settings): string {
                if (!isset($settings[$path])) {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000006);
                }

                return $settings[$path];
            }
        );

        return new PatternStorageSettings($extensionConfiguration, $logger);
    }

    /**
     * @return AbstractLogger&object{records: list<array{level: string, message: string}>}
     */
    private function createSpyLogger(): AbstractLogger
    {
        return new class extends AbstractLogger {
            /** @var list<array{level: string, message: string}> */
            public array $records = [];

            public function log(mixed $level, \Stringable|string $message, array $context = []): void
            {
                $this->records[] = ['level' => is_string($level) ? $level : 'unknown', 'message' => (string)$message];
            }
        };
    }
}
