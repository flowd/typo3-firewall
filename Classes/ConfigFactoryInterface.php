<?php

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;

interface ConfigFactoryInterface
{
    public function fromConfigurationFile(): Config;

    public function getConfigurationPath(): string;

    public function getPatternsFilePath(): string;

    public static function getBaseConfigPath(): string;
}
