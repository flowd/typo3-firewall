<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

/**
 * Typed access to the event log settings from the extension configuration.
 */
final class EventLogSettings
{
    private bool $deprecatedTypeReported = false;

    public function __construct(
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    public function isEnabled(): bool
    {
        return (bool)$this->getSetting('eventLogEnabled', '1');
    }

    public function isTypeEnabled(FirewallEventType $firewallEventType): bool
    {
        return in_array($firewallEventType, $this->enabledTypes(), true);
    }

    /**
     * The configured event types, unknown values dropped and deprecated values
     * expanded to their successors. A deprecated value logs one deprecation
     * per instance.
     *
     * @return list<FirewallEventType>
     */
    private function enabledTypes(): array
    {
        $enabledTypes = [];
        foreach (explode(',', $this->getSetting('eventLogTypes', '')) as $configuredValue) {
            $configuredType = FirewallEventType::tryFrom(trim($configuredValue));
            if (!$configuredType instanceof FirewallEventType) {
                continue;
            }

            $enabledByValue = $configuredType->enables();
            if ($enabledByValue !== [$configuredType] && !$this->deprecatedTypeReported) {
                $this->deprecatedTypeReported = true;
                trigger_error(
                    sprintf(
                        'The firewall event log type "%s" is deprecated, configure "%s" instead (eventLogTypes extension setting).',
                        $configuredType->value,
                        implode(', ', array_map(static fn(FirewallEventType $firewallEventType): string => $firewallEventType->value, $enabledByValue)),
                    ),
                    E_USER_DEPRECATED,
                );
            }

            array_push($enabledTypes, ...$enabledByValue);
        }

        return $enabledTypes;
    }

    public function getRetentionDays(): int
    {
        return max(1, (int)$this->getSetting('eventLogRetentionDays', '30'));
    }

    public function isIpAnonymizationEnabled(): bool
    {
        return (bool)$this->getSetting('eventLogAnonymizeIp', '1');
    }

    /**
     * Rules whose events store the client IP unanonymized, as a targeted
     * exception from the anonymization setting while an attack is analyzed.
     *
     * @return list<string>
     */
    public function getFullIpLoggingRules(): array
    {
        $rules = [];
        foreach (explode(',', $this->getSetting('eventLogFullIpRules', '')) as $configuredRule) {
            $configuredRule = trim($configuredRule);
            if ($configuredRule !== '' && !in_array($configuredRule, $rules, true)) {
                $rules[] = $configuredRule;
            }
        }

        return $rules;
    }

    public function isFullIpLoggingEnabledForRule(string $rule): bool
    {
        return $rule !== '' && in_array($rule, $this->getFullIpLoggingRules(), true);
    }

    public function isRequestHeaderLoggingEnabled(): bool
    {
        return (bool)$this->getSetting('eventLogRequestHeaders', '0');
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
