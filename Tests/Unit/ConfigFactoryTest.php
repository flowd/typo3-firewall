<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Phirewall\Store\PdoCache;
use Flowd\Typo3Firewall\ConfigFactory;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\ListenerProviderInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\EventDispatcher\EventDispatcher;
use TYPO3\CMS\Core\Http\ServerRequest;

#[CoversClass(ConfigFactory::class)]
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

    private function createFactory(?LoggerInterface $logger = null): ConfigFactory
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

        return new ConfigFactory(new EventDispatcher($listenerProvider), $logger);
    }

    private function writeConfigurationFile(string $content): string
    {
        $vfsStreamDirectory = vfsStream::setup('config');
        vfsStream::newFile('phirewall.php')->at($vfsStreamDirectory)->setContent($content);

        return vfsStream::url('config/phirewall.php');
    }
}
