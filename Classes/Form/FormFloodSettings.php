<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Form;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

/**
 * Typed access to the form flood protection settings from the extension
 * configuration.
 */
final class FormFloodSettings
{
    /**
     * Name of the allow2ban rule the default form flood protection registers
     * and the finisher feeds. Shared between ConfigFactory (which registers
     * the rule) and the finisher (which reports submissions to it).
     */
    public const string DEFAULT_RULE_IDENTIFIER = 'form-flood';

    public function __construct(
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    public function isEnabled(): bool
    {
        return (bool)$this->getSetting('formFloodEnabled', '0');
    }

    public function getThreshold(): int
    {
        return max(1, (int)$this->getSetting('formFloodThreshold', '5'));
    }

    public function getPeriod(): int
    {
        return max(1, (int)$this->getSetting('formFloodPeriod', '60'));
    }

    public function getBanSeconds(): int
    {
        return max(1, (int)$this->getSetting('formFloodBan', '3600'));
    }

    private function getSetting(string $settingName, string $default): string
    {
        try {
            $value = $this->extensionConfiguration->get('firewall', $settingName);
        } catch (\Throwable) {
            return $default;
        }

        return is_scalar($value) ? (string)$value : $default;
    }
}
