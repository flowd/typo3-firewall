<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Phirewall\Store\PdoCache;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Form\FormFloodSettings;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\ListenerProviderInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\EventDispatcher\EventDispatcher;
use TYPO3\CMS\Core\Http\ServerRequest;

#[CoversClass(ConfigFactory::class)]
#[UsesClass(FormFloodSettings::class)]
final class ConfigFactoryTest extends TestCase
{
    private const string CONFIG_WITHOUT_IP_RESOLVER = <<<'PHP'
        <?php
        use Flowd\Phirewall\Config;
        use Flowd\Phirewall\Store\InMemoryCache;
        use Psr\EventDispatcher\EventDispatcherInterface;

        return function (EventDispatcherInterface $eventDispatcher): Config {
            return new Config(new InMemoryCache(), $eventDispatcher);
        };
        PHP;

    private const string CONFIG_WITH_IP_RESOLVER = <<<'PHP'
        <?php
        use Flowd\Phirewall\Config;
        use Flowd\Phirewall\Store\InMemoryCache;
        use Psr\EventDispatcher\EventDispatcherInterface;

        return function (EventDispatcherInterface $eventDispatcher): Config {
            $config = new Config(new InMemoryCache(), $eventDispatcher);
            $config->setIpResolver(fn(): string => '198.51.100.9');
            return $config;
        };
        PHP;

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

    #[Test]
    public function fromFileSetsDefaultIpResolverWhenConfigurationDoesNotSetOne(): void
    {
        $configPath = $this->writeConfigurationFile(self::CONFIG_WITHOUT_IP_RESOLVER);

        $config = $this->createFactory()->fromFile($configPath);

        self::assertInstanceOf(\Closure::class, $config->getIpResolver());
    }

    #[Test]
    public function fromFileKeepsTheIpResolverOfTheConfigurationFile(): void
    {
        $configPath = $this->writeConfigurationFile(self::CONFIG_WITH_IP_RESOLVER);

        $config = $this->createFactory()->fromFile($configPath);
        $ipResolver = $config->getIpResolver();

        self::assertInstanceOf(\Closure::class, $ipResolver);
        self::assertSame('198.51.100.9', $ipResolver(new ServerRequest()));
    }

    #[Test]
    public function fromFileKeepsTheCacheOfTheConfigurationFile(): void
    {
        $configPath = $this->writeConfigurationFile(<<<'PHP'
            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\PdoCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                return new Config(new PdoCache(new \PDO('sqlite::memory:')), $eventDispatcher);
            };
            PHP);

        $config = $this->createFactory()->fromFile($configPath);

        self::assertInstanceOf(PdoCache::class, $config->cache);
    }

    #[Test]
    public function fromFileAddsTheBackendPatternsBlocklistFirst(): void
    {
        $configPath = $this->writeConfigurationFile(self::CONFIG_WITHOUT_IP_RESOLVER);

        $config = $this->createFactory()->fromFile($configPath);

        self::assertSame('typo3-blocklist', array_key_first($config->blocklists->rules()));
    }

    #[Test]
    public function fromFileLetsTheConfigurationOverrideTheBackendPatternsBlocklist(): void
    {
        $configPath = $this->writeConfigurationFile(<<<'PHP'
            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\InMemoryCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new InMemoryCache(), $eventDispatcher);
                $config->blocklists->add(
                    name: 'typo3-blocklist',
                    callback: fn($request): bool => $request->getUri()->getPath() === '/overridden'
                );
                return $config;
            };
            PHP);

        $config = $this->createFactory()->fromFile($configPath);
        $rules = $config->blocklists->rules();

        self::assertArrayHasKey('typo3-blocklist', $rules);
        self::assertTrue($rules['typo3-blocklist']->matcher()->match(new ServerRequest('https://example.com/overridden'))->isMatch());
    }

    #[Test]
    public function fromFileFallsBackToDefaultConfigWithDefaultIpResolver(): void
    {
        vfsStream::setup('config');

        $config = $this->createFactory()->fromFile(vfsStream::url('config/missing.php'));

        self::assertInstanceOf(\Closure::class, $config->getIpResolver());
    }

    #[Test]
    public function fromFileFallsBackAndLogsAnErrorWhenTheConfigurationThrows(): void
    {
        $configPath = $this->writeConfigurationFile('<?php return function () { throw new \RuntimeException(\'boom\'); };');
        $spyLogger = $this->createSpyLogger();

        $config = $this->createFactory($spyLogger)->fromFile($configPath);

        self::assertInstanceOf(\Closure::class, $config->getIpResolver());
        self::assertCount(1, $spyLogger->records);
        self::assertSame('error', $spyLogger->records[0]['level']);
        self::assertStringContainsString('boom', $spyLogger->records[0]['message']);
    }

    #[Test]
    public function fromFileFallsBackAndLogsAnErrorOnASyntaxError(): void
    {
        $configPath = $this->writeConfigurationFile('<?php return function ( { broken');
        $spyLogger = $this->createSpyLogger();

        $config = $this->createFactory($spyLogger)->fromFile($configPath);

        self::assertInstanceOf(\Closure::class, $config->getIpResolver());
        self::assertCount(1, $spyLogger->records);
        self::assertSame('error', $spyLogger->records[0]['level']);
    }

    #[Test]
    public function fromFileLogsAPdoDriverHintForTheMysqliTypeError(): void
    {
        $configPath = $this->writeConfigurationFile(
            '<?php return function () { throw new \TypeError(\'PdoCache::__construct(): Argument #1 ($pdo) must be of type PDO, mysqli given\'); };'
        );
        $spyLogger = $this->createSpyLogger();

        $this->createFactory($spyLogger)->fromFile($configPath);

        self::assertCount(1, $spyLogger->records);
        self::assertStringContainsString('pdo_mysql', $spyLogger->records[0]['message']);
        self::assertStringContainsString('mysqli driver', $spyLogger->records[0]['message']);
    }

    #[Test]
    public function fromFileWarnsWhenThrottleRulesRunOnTheInMemoryStore(): void
    {
        $configPath = $this->writeConfigurationFile(<<<'PHP'
            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\InMemoryCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new InMemoryCache(), $eventDispatcher);
                $config->throttles->add(name: 'api-throttle', limit: 10, period: 60);
                return $config;
            };
            PHP);
        $spyLogger = $this->createSpyLogger();

        $this->createFactory($spyLogger, cli: false)->fromFile($configPath);

        self::assertCount(1, $spyLogger->records);
        self::assertSame('warning', $spyLogger->records[0]['level']);
        self::assertStringContainsString('InMemoryCache', $spyLogger->records[0]['message']);
    }

    #[Test]
    public function fromFileDoesNotWarnOnCliOrWithoutCounterRules(): void
    {
        $throttleConfig = <<<'PHP'
            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\InMemoryCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new InMemoryCache(), $eventDispatcher);
                $config->throttles->add(name: 'api-throttle', limit: 10, period: 60);
                return $config;
            };
            PHP;

        $cliLogger = $this->createSpyLogger();
        $this->createFactory($cliLogger, cli: true)->fromFile($this->writeConfigurationFile($throttleConfig));
        self::assertSame([], $cliLogger->records);

        $blocklistOnlyLogger = $this->createSpyLogger();
        $this->createFactory($blocklistOnlyLogger, cli: false)->fromFile($this->writeConfigurationFile(self::CONFIG_WITHOUT_IP_RESOLVER));
        self::assertSame([], $blocklistOnlyLogger->records);
    }

    #[Test]
    public function noFormFloodRuleIsRegisteredWhenTheProtectionIsDisabled(): void
    {
        vfsStream::setup('config');

        $config = $this->createFactory()->fromFile(vfsStream::url('config/missing.php'));

        self::assertArrayNotHasKey('form-flood', $config->allow2ban->rules());
    }

    #[Test]
    public function theFormFloodRuleIsRegisteredWithItsDefaultsWhenEnabled(): void
    {
        vfsStream::setup('config');
        $formFloodSettings = $this->createFormFloodSettings(['formFloodEnabled' => '1']);

        $config = $this->createFactory(formFloodSettings: $formFloodSettings)->fromFile(vfsStream::url('config/missing.php'));

        $rules = $config->allow2ban->rules();
        self::assertArrayHasKey('form-flood', $rules);
        self::assertSame(5, $rules['form-flood']->threshold());
        self::assertSame(60, $rules['form-flood']->period());
        self::assertSame(3600, $rules['form-flood']->banSeconds());
    }

    #[Test]
    public function theFormFloodRuleUsesTheConfiguredThresholdPeriodAndBan(): void
    {
        vfsStream::setup('config');
        $formFloodSettings = $this->createFormFloodSettings([
            'formFloodEnabled' => '1',
            'formFloodThreshold' => '7',
            'formFloodPeriod' => '120',
            'formFloodBan' => '600',
        ]);

        $config = $this->createFactory(formFloodSettings: $formFloodSettings)->fromFile(vfsStream::url('config/missing.php'));

        $formFloodRule = $config->allow2ban->rules()['form-flood'];
        self::assertSame(7, $formFloodRule->threshold());
        self::assertSame(120, $formFloodRule->period());
        self::assertSame(600, $formFloodRule->banSeconds());
    }

    #[Test]
    public function aFormFloodRuleInTheConfigurationFileWinsOverTheGeneratedDefault(): void
    {
        $configPath = $this->writeConfigurationFile(<<<'PHP'
            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\InMemoryCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new InMemoryCache(), $eventDispatcher);
                $config->allow2ban->add(
                    'form-flood',
                    threshold: 99,
                    period: 90,
                    banSeconds: 900,
                    filter: static fn(): bool => false,
                );
                return $config;
            };
            PHP);
        $formFloodSettings = $this->createFormFloodSettings(['formFloodEnabled' => '1', 'formFloodThreshold' => '7']);

        $config = $this->createFactory(formFloodSettings: $formFloodSettings)->fromFile($configPath);

        self::assertSame(99, $config->allow2ban->rules()['form-flood']->threshold());
    }

    #[Test]
    public function theDefaultConfigWarnsWhenTheFormFloodRuleRunsOnTheInMemoryStore(): void
    {
        vfsStream::setup('config');
        $spyLogger = $this->createSpyLogger();
        $formFloodSettings = $this->createFormFloodSettings(['formFloodEnabled' => '1']);

        $this->createFactory($spyLogger, cli: false, formFloodSettings: $formFloodSettings)->fromFile(vfsStream::url('config/missing.php'));

        self::assertCount(1, $spyLogger->records);
        self::assertSame('warning', $spyLogger->records[0]['level']);
        self::assertStringContainsString('InMemoryCache', $spyLogger->records[0]['message']);
    }

    /**
     * @return AbstractLogger&object{records: list<array{level: string, message: string}>}
     */
    private function createSpyLogger(): AbstractLogger
    {
        return new class () extends AbstractLogger {
            /** @var list<array{level: string, message: string}> */
            public array $records = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->records[] = ['level' => is_string($level) ? $level : 'unknown', 'message' => (string)$message];
            }
        };
    }

    private function createFactory(?LoggerInterface $logger = null, bool $cli = true, ?FormFloodSettings $formFloodSettings = null): ConfigFactory
    {
        $listenerProvider = new class () implements ListenerProviderInterface {
            /**
             * @return list<callable>
             */
            public function getListenersForEvent(object $event): iterable
            {
                return [];
            }
        };

        $formFloodSettings ??= $this->createFormFloodSettings([]);

        return new class (new EventDispatcher($listenerProvider), $formFloodSettings, $logger, $cli) extends ConfigFactory {
            public function __construct(EventDispatcher $eventDispatcher, FormFloodSettings $formFloodSettings, ?LoggerInterface $logger, private readonly bool $cli)
            {
                parent::__construct($eventDispatcher, $formFloodSettings, $logger);
            }

            protected function isCliRequest(): bool
            {
                return $this->cli;
            }
        };
    }

    /**
     * @param array<string, string> $settings
     */
    private function createFormFloodSettings(array $settings): FormFloodSettings
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($settings): string {
                self::assertSame('firewall', $extension);
                if (!isset($settings[$path])) {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000003);
                }

                return $settings[$path];
            }
        );

        return new FormFloodSettings($extensionConfiguration);
    }

    private function writeConfigurationFile(string $content): string
    {
        $vfsStreamDirectory = vfsStream::setup('config');
        vfsStream::newFile('phirewall.php')->at($vfsStreamDirectory)->setContent($content);

        return vfsStream::url('config/phirewall.php');
    }
}
