<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\Pattern\PhpArrayPatternBackend;
use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\EventDispatcher\EventDispatcher;

#[Autoconfigure(autowire: true)]
class ConfigFactory
{
    public function __construct(private readonly EventDispatcher $eventDispatcher) {}

    public function fromConfigurationFile(): Config
    {
        if (@is_file($this->getConfigurationPath())) {
            $configClosure = require $this->getConfigurationPath();
            $config = null;

            if ($configClosure instanceof \Closure) {
                $config = $configClosure($this->eventDispatcher);
            }

            if ($config instanceof Config) {
                $config->addPatternBackend(
                    'typo3-managed-patterns',
                    new PhpArrayPatternBackend(Environment::getConfigPath() . '/system/phirewall.patterns.php')
                );
                return $config;
            }
        }

        return $this->getDefaultConfig();
    }

    private function getDefaultConfig(): Config
    {
        return (new Config(new InMemoryCache(), $this->eventDispatcher))
            ->addPatternBackend(
                'typo3-managed-patterns',
                new PhpArrayPatternBackend(Environment::getConfigPath() . '/system/phirewall.patterns.php')
            );
    }

    private function getConfigurationPath(): string
    {
        if (Environment::getProjectPath() !== Environment::getPublicPath()) {
            return Environment::getConfigPath() . '/system/phirewall.php';
        }

        return Environment::getLegacyConfigPath() . '/system/phirewall.php';
    }
}
