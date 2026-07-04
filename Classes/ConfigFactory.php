<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\EventDispatcher\EventDispatcher;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[Autoconfigure(autowire: true)]
class ConfigFactory
{
    public function __construct(
        private readonly EventDispatcher $eventDispatcher,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function fromConfigurationFile(): Config
    {
        return $this->fromFile(self::getConfigurationPath());
    }

    public function fromFile(string $configPath): Config
    {
        if (is_file($configPath)) {
            $configClosure = require $configPath;
            $config = null;

            if ($configClosure instanceof \Closure) {
                $config = $configClosure($this->eventDispatcher);
            }

            if ($config instanceof Config) {
                return $this->prepareConfig($config);
            }

            $this->logger?->warning('Invalid phirewall.php configuration file', ['path' => $configPath]);
        }

        return $this->getDefaultConfig();
    }

    private function getDefaultConfig(): Config
    {
        return $this->prepareConfig(new Config(new InMemoryCache(), $this->eventDispatcher));
    }

    private function prepareConfig(Config $config): Config
    {
        $this->applyDefaultIpResolver($config);
        return $this->addTypo3ManagedPatternsBlocklist($config);
    }

    private function applyDefaultIpResolver(Config $config): void
    {
        if ($config->getIpResolver() instanceof \Closure) {
            return;
        }

        // getIndpEnv() applies TYPO3's reverseProxyIP settings, so rules key on the real client IP.
        $config->setIpResolver(static function (): ?string {
            $remoteAddress = GeneralUtility::getIndpEnv('REMOTE_ADDR');
            return is_string($remoteAddress) && $remoteAddress !== '' ? $remoteAddress : null;
        });
    }

    private function addTypo3ManagedPatternsBlocklist(Config $config): Config
    {
        $patternPath = self::getPatternsFilePath();
        $fileArrayPatternBackend = new FileArrayPatternBackend($patternPath, new FileArrayWriter($patternPath, $this->logger), $this->logger);

        $config->blocklists->addPatternBackend('typo3-managed-patterns', $fileArrayPatternBackend)->fromBackend('typo3-blocklist', 'typo3-managed-patterns');
        return $config;
    }

    public static function getBaseConfigPath(): string
    {
        if (Environment::getProjectPath() !== Environment::getPublicPath()) {
            return Environment::getConfigPath();
        }

        return Environment::getLegacyConfigPath();
    }

    public static function getConfigurationPath(): string
    {
        return self::getBaseConfigPath() . '/system/phirewall.php';
    }

    public static function getPatternsFilePath(): string
    {
        return self::getBaseConfigPath() . '/system/phirewall.patterns.json';
    }
}
