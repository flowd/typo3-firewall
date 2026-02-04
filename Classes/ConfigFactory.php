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

#[Autoconfigure(autowire: true)]
class ConfigFactory
{
    public function __construct(
        private readonly EventDispatcher $eventDispatcher,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function fromConfigurationFile(): Config
    {
        $configPath = self::getConfigurationPath();

        if (is_file($configPath)) {
            $configClosure = require $configPath;
            $config = null;

            if ($configClosure instanceof \Closure) {
                $config = $configClosure($this->eventDispatcher);
            }

            if ($config instanceof Config) {
                return $this->addTypo3ManagedPatternsBlocklist($config);
            }

            $this->logger?->warning('Invalid phirewall.php configuration file', ['path' => $configPath]);
        }

        return $this->getDefaultConfig();
    }

    private function getDefaultConfig(): Config
    {
        return $this->addTypo3ManagedPatternsBlocklist(new Config(new InMemoryCache(), $this->eventDispatcher));
    }

    private function addTypo3ManagedPatternsBlocklist(Config $config): Config
    {
        $patternPath = self::getPatternsFilePath();
        $fileArrayPatternBackend = new FileArrayPatternBackend($patternPath, new FileArrayWriter($patternPath, $this->logger), $this->logger);

        return $config->addPatternBackend('typo3-managed-patterns', $fileArrayPatternBackend)
            ->blocklistFromBackend('typo3-blocklist', 'typo3-managed-patterns');
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
