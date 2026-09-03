<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

/**
 * Why a logged key is currently blocked: an active ban or a blocklist
 * pattern entry.
 */
final readonly class KeyBlockStatus
{
    public const string SOURCE_BAN = 'ban';

    public const string SOURCE_PATTERN = 'pattern';

    /**
     * @param string $source One of the SOURCE_* constants
     * @param string $detail Human readable origin, e.g. "login (fail2ban)" or "cidr 1.2.3.0/24"
     */
    public function __construct(
        public string $source,
        public string $detail,
    ) {}
}
