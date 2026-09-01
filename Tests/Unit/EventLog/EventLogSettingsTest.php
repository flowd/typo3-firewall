<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\EventLog;

use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Flowd\Typo3Firewall\EventLog\FirewallEventType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

#[CoversClass(EventLogSettings::class)]
final class EventLogSettingsTest extends TestCase
{
    #[Test]
    public function loggingIsEnabledByDefaultWhenConfigurationIsMissing(): void
    {
        $eventLogSettings = $this->createSettings([]);

        self::assertTrue($eventLogSettings->isEnabled());
    }

    #[Test]
    public function loggingCanBeDisabled(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogEnabled' => '0']);

        self::assertFalse($eventLogSettings->isEnabled());
    }

    #[Test]
    public function configuredTypesAreParsedFromTheCommaSeparatedList(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogTypes' => 'blocklist_matched, fail2ban_banned']);

        self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::BlocklistMatched));
        self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::Fail2BanBanned));
        self::assertFalse($eventLogSettings->isTypeEnabled(FirewallEventType::SafelistMatched));
    }

    #[Test]
    public function trackTypesAreIndividuallyConfigurable(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogTypes' => 'track_threshold_reached']);

        self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::TrackThresholdReached));
        self::assertFalse($eventLogSettings->isTypeEnabled(FirewallEventType::TrackMatched));
    }

    #[Test]
    #[IgnoreDeprecations]
    public function deprecatedTrackHitTypeEnablesBothTrackTypes(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogTypes' => 'track_hit']);

        self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::TrackThresholdReached));
        self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::TrackMatched));
        self::assertFalse($eventLogSettings->isTypeEnabled(FirewallEventType::ThrottleExceeded));
    }

    #[Test]
    public function deprecatedTrackHitTypeTriggersOneDeprecation(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogTypes' => 'track_hit']);

        $deprecations = [];
        set_error_handler(static function (int $errorNumber, string $errorMessage) use (&$deprecations): bool {
            $deprecations[] = $errorMessage;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $eventLogSettings->isTypeEnabled(FirewallEventType::TrackThresholdReached);
            $eventLogSettings->isTypeEnabled(FirewallEventType::TrackMatched);
        } finally {
            restore_error_handler();
        }

        self::assertCount(1, $deprecations, 'The deprecation is logged once per instance, not once per check');
        self::assertStringContainsString('track_hit', $deprecations[0]);
        self::assertStringContainsString('track_matched', $deprecations[0]);
        self::assertStringContainsString('track_threshold_reached', $deprecations[0]);
    }

    #[Test]
    public function currentTypeValuesTriggerNoDeprecation(): void
    {
        $eventLogSettings = $this->createSettings(['eventLogTypes' => 'track_matched, track_threshold_reached']);

        $deprecations = [];
        set_error_handler(static function (int $errorNumber, string $errorMessage) use (&$deprecations): bool {
            $deprecations[] = $errorMessage;

            return true;
        }, E_USER_DEPRECATED);

        try {
            self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::TrackMatched));
            self::assertTrue($eventLogSettings->isTypeEnabled(FirewallEventType::TrackThresholdReached));
        } finally {
            restore_error_handler();
        }

        self::assertSame([], $deprecations);
    }

    #[Test]
    public function retentionDaysFallBackToThirtyAndNeverGoBelowOne(): void
    {
        self::assertSame(30, $this->createSettings([])->getRetentionDays());
        self::assertSame(7, $this->createSettings(['eventLogRetentionDays' => '7'])->getRetentionDays());
        self::assertSame(1, $this->createSettings(['eventLogRetentionDays' => '0'])->getRetentionDays());
    }

    #[Test]
    public function ipAnonymizationIsEnabledByDefault(): void
    {
        self::assertTrue($this->createSettings([])->isIpAnonymizationEnabled());
        self::assertFalse($this->createSettings(['eventLogAnonymizeIp' => '0'])->isIpAnonymizationEnabled());
    }

    /**
     * @param array<string, string> $settings
     */
    private function createSettings(array $settings): EventLogSettings
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($settings): string {
                if (!isset($settings[$path])) {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000001);
                }

                return $settings[$path];
            }
        );

        return new EventLogSettings($extensionConfiguration);
    }
}
