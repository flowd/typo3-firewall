<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

enum FirewallEventType: string
{
    case BlocklistMatched = 'blocklist_matched';

    case ThrottleExceeded = 'throttle_exceeded';

    case Fail2BanMatched = 'fail2ban_matched';

    case Fail2BanBanned = 'fail2ban_banned';

    case Fail2BanBlocked = 'fail2ban_blocked';

    case Allow2BanBanned = 'allow2ban_banned';

    case Allow2BanBlocked = 'allow2ban_blocked';

    case SafelistMatched = 'safelist_matched';

    case TrackMatched = 'track_matched';

    case TrackThresholdReached = 'track_threshold_reached';

    /**
     * @deprecated Split into {@see self::TrackMatched} (every hit) and
     *             {@see self::TrackThresholdReached} (limit set and count >= limit). Never
     *             written anymore; kept so existing rows stay readable and filterable. A
     *             configured track_hit enables both successors via {@see enables()}.
     */
    case TrackHit = 'track_hit';

    case FirewallError = 'firewall_error';

    /**
     * The types a configured value enables: a deprecated value expands to its
     * successors, every current value to itself.
     *
     * @return list<self>
     */
    public function enables(): array
    {
        return $this === self::TrackHit
            ? [self::TrackMatched, self::TrackThresholdReached]
            : [$this];
    }

    /**
     * Event types that represent a blocked attacker, used for statistics.
     *
     * @return list<self>
     */
    public static function blockingTypes(): array
    {
        return [self::BlocklistMatched, self::ThrottleExceeded, self::Fail2BanMatched, self::Fail2BanBanned, self::Fail2BanBlocked, self::Allow2BanBanned, self::Allow2BanBlocked];
    }
}
