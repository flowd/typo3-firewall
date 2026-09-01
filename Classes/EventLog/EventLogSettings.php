<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

/**
 * Typed access to the event log settings from the extension configuration.
 */
final class EventLogSettings
{
    public function __construct(
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    public function isEnabled(): bool
    {
        return (bool)$this->getSetting('eventLogEnabled', '1');
    }

    public function isTypeEnabled(FirewallEventType $firewallEventType): bool
    {
        $configuredTypes = array_map(
            trim(...),
            explode(',', $this->getSetting('eventLogTypes', ''))
        );

        return in_array($firewallEventType->value, $configuredTypes, true);
    }

    public function getRetentionDays(): int
    {
        return max(1, (int)$this->getSetting('eventLogRetentionDays', '30'));
    }

    public function isIpAnonymizationEnabled(): bool
    {
        return (bool)$this->getSetting('eventLogAnonymizeIp', '1');
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
