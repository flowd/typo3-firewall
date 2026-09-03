<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

/**
 * Filter criteria for event log queries.
 *
 * @see EventLogRepository
 */
final readonly class EventLogFilter
{
    /**
     * @param list<string> $eventTypes Event type values, empty for all types
     * @param string $search Substring match on rule, key display and request path, or a full raw key
     * @param string $keyHash Keyed hash of a single key to drill down into
     * @param string $rule Exact rule name
     * @param int $since Minimum created_at timestamp, 0 for no lower bound
     * @param list<string> $excludeKeyHashes Key hashes whose events are hidden
     */
    public function __construct(
        public array $eventTypes = [],
        public string $search = '',
        public string $keyHash = '',
        public string $rule = '',
        public int $since = 0,
        public array $excludeKeyHashes = [],
    ) {}
}
