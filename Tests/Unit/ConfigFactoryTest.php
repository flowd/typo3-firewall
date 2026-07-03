<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Typo3Firewall\ConfigFactory;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\ListenerProviderInterface;
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
    public function fromFileFallsBackToDefaultConfigWithDefaultIpResolver(): void
    {
        vfsStream::setup('config');

        $config = $this->createFactory()->fromFile(vfsStream::url('config/missing.php'));

        self::assertInstanceOf(\Closure::class, $config->getIpResolver());
    }

    private function createFactory(): ConfigFactory
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

        return new ConfigFactory(new EventDispatcher($listenerProvider));
    }

    private function writeConfigurationFile(string $content): string
    {
        $vfsStreamDirectory = vfsStream::setup('config');
        vfsStream::newFile('phirewall.php')->at($vfsStreamDirectory)->setContent($content);

        return vfsStream::url('config/phirewall.php');
    }
}
