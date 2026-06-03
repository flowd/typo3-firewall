<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Fixtures;

use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;

class FixtureConfigFactory extends ConfigFactory
{
    public function __construct(
        EventDispatcherInterface $eventDispatcher,
        ExtensionConfiguration $extensionConfiguration,
        ?LoggerInterface $logger = null,
        private readonly ?string $fixtureName = null,
    ) {
        parent::__construct($eventDispatcher, $extensionConfiguration, $logger);
    }

    public static function getBaseConfigPath(): string
    {
        return __DIR__;
    }

    public function getConfigurationPath(): string
    {
        return $this->getSuffixedFile('phirewall.php');
    }

    public function getPatternsFilePath(): string
    {
        return $this->getSuffixedFile('phirewall.patterns.json');
    }

    public function getSuffixedFile(string $filename): string
    {
        if (is_string($this->fixtureName)) {
            $filename = $this->fixtureName . '.' . $filename;
        }

        return static::getBaseConfigPath() . sprintf('/system/%s', $filename);
    }
}
