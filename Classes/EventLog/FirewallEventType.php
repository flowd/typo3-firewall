<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

enum FirewallEventType: string
{
    case BlocklistMatched = 'blocklist_matched';

    case ThrottleExceeded = 'throttle_exceeded';

    case Fail2BanMatched = 'fail2ban_matched';

    case Fail2BanBanned = 'fail2ban_banned';

    case Allow2BanBanned = 'allow2ban_banned';

    case SafelistMatched = 'safelist_matched';

    case TrackHit = 'track_hit';

    case FirewallError = 'firewall_error';

    /**
     * Event types that represent a blocked attacker, used for statistics.
     *
     * @return list<self>
     */
    public static function blockingTypes(): array
    {
        return [self::BlocklistMatched, self::ThrottleExceeded, self::Fail2BanMatched, self::Fail2BanBanned, self::Allow2BanBanned];
    }
}
