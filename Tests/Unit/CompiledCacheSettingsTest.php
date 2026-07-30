<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Typo3Firewall\CompiledCacheSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
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
    public function aConfiguredDirectoryWithinTheProjectWins(): void
    {
        $directory = Environment::getProjectPath() . '/var/compiled-cache';
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => $directory]);

        self::assertSame($directory, $compiledCacheSettings->getDirectory());
    }

    #[Test]
    public function aTrailingSlashInTheConfiguredDirectoryIsIgnored(): void
    {
        $directory = Environment::getProjectPath() . '/var/compiled-cache';
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => $directory . '/']);

        self::assertSame($directory, $compiledCacheSettings->getDirectory());
    }

    #[Test]
    public function aBlankConfiguredDirectoryFallsBack(): void
    {
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => '   ']);

        self::assertSame(Environment::getVarPath() . '/cache/code/firewall', $compiledCacheSettings->getDirectory());
    }

    #[Test]
    public function aDirectoryOutsideTheAllowedPathsFallsBackAndWarns(): void
    {
        $logger = $this->createSpyLogger();
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => '/srv/cache/phirewall'], $logger);

        self::assertSame(Environment::getVarPath() . '/cache/code/firewall', $compiledCacheSettings->getDirectory());
        self::assertCount(1, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
    }

    #[Test]
    public function aPathTraversalInTheConfiguredDirectoryFallsBack(): void
    {
        $directory = Environment::getProjectPath() . '/var/../../outside';
        $compiledCacheSettings = $this->createSettings(['compiledCacheDirectory' => $directory]);

        self::assertSame(Environment::getVarPath() . '/cache/code/firewall', $compiledCacheSettings->getDirectory());
    }

    /**
     * @param array<string, string> $settings
     */
    private function createSettings(array $settings, ?LoggerInterface $logger = null): CompiledCacheSettings
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

        return new CompiledCacheSettings($extensionConfiguration, $logger);
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
