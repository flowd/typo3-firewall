<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Typo3Firewall\Statistics\BarChartBuilder;

/**
 * Assembles the view data for the event log module view.
 *
 * Without a key filter the timeline collapses each key to its newest three
 * events and marks the last visible row of a collapsed key with the number
 * of hidden events. With a key filter every event of that key is listed.
 */
final class EventLogViewDataProvider
{
    /** Time ranges offered by the view, as window seconds; 0 means unbounded. */
    public const array RANGES = [
        '24h' => 86400,
        '7d' => 604800,
        '30d' => 2592000,
        'all' => 0,
    ];

    public const string DEFAULT_RANGE = '7d';

    /** Bounds the NOT IN clause and the URL length of the filter links. */
    public const int MAX_EXCLUDED_KEYS = 20;

    private const int ITEMS_PER_PAGE = 50;

    private const int EVENTS_PER_KEY = 3;

    /** Dot and tag color for event types outside the chart palette. */
    private const string NEUTRAL_TYPE_COLOR = '#6b7280';

    public function __construct(
        private readonly EventLogRepository $eventLogRepository,
        private readonly EventLogSettings $eventLogSettings,
        private readonly BarChartBuilder $barChartBuilder,
        private readonly KeyBlockStatusProvider $keyBlockStatusProvider,
        private readonly BlockableKeyResolver $blockableKeyResolver,
    ) {}

    /**
     * View variables for the event log view; unknown types, ranges and
     * malformed key hashes fall back to the unfiltered view, out-of-range
     * pages are clamped.
     *
     * @param array<mixed> $types
     * @param array<mixed> $excludeKeys
     * @return array<string, mixed>
     */
    public function getViewData(array $types, string $search, string $keyHash, string $rule = '', int $page = 1, array $excludeKeys = [], string $range = ''): array
    {
        $currentTypes = $this->sanitizeTypes($types);
        $keyHash = preg_match('/^[a-f0-9]{64}$/', $keyHash) === 1 ? $keyHash : '';
        $rule = mb_substr(trim($rule), 0, 255);
        $excludeKeyHashes = self::sanitizeExcludeKeys($excludeKeys);
        $range = isset(self::RANGES[$range]) ? $range : self::DEFAULT_RANGE;

        $eventLogFilter = new EventLogFilter(
            eventTypes: $currentTypes,
            search: $search,
            keyHash: $keyHash,
            rule: $rule,
            since: self::RANGES[$range] === 0 ? 0 : time() - self::RANGES[$range],
            excludeKeyHashes: $excludeKeyHashes,
        );

        $viewData = $keyHash === ''
            ? $this->buildCollapsedTimelineData($eventLogFilter, $page)
            : $this->buildKeyFilterData($eventLogFilter, $page);

        return [
            ...$viewData,
            'typeFilters' => $this->buildTypeFilters($currentTypes),
            'currentTypes' => $currentTypes,
            'search' => $search,
            'ruleFilter' => $rule === '' ? null : $rule,
            'range' => $range,
            'ranges' => array_keys(self::RANGES),
            'excludeKeyHashes' => $excludeKeyHashes,
            'excludedKeyChips' => $this->buildExcludedKeyChips($excludeKeyHashes),
            'fullIpLoggingRules' => implode(', ', $this->eventLogSettings->getFullIpLoggingRules()),
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
            'pruneOverdue' => $this->isPruneOverdue(),
        ];
    }

    /**
     * Keep only well-formed key hashes, without duplicates, capped at
     * MAX_EXCLUDED_KEYS.
     *
     * @param array<mixed> $excludeKeys
     * @return list<string>
     */
    public static function sanitizeExcludeKeys(array $excludeKeys): array
    {
        $sanitized = [];
        foreach ($excludeKeys as $excludeKey) {
            if (is_string($excludeKey) && preg_match('/^[a-f0-9]{64}$/', $excludeKey) === 1 && !in_array($excludeKey, $sanitized, true)) {
                $sanitized[] = $excludeKey;
            }

            if (count($sanitized) === self::MAX_EXCLUDED_KEYS) {
                break;
            }
        }

        return $sanitized;
    }

    /**
     * Timeline with at most three events per key; rows hitting that cap carry
     * a moreEventsCount with the number of older events hidden behind the key
     * filter link.
     *
     * @return array<string, mixed>
     */
    private function buildCollapsedTimelineData(EventLogFilter $eventLogFilter, int $page): array
    {
        $rowCount = $this->eventLogRepository->countCollapsedByKey($eventLogFilter, self::EVENTS_PER_KEY);
        $pageCount = max(1, (int)ceil($rowCount / self::ITEMS_PER_PAGE));
        $page = min(max(1, $page), $pageCount);

        $events = array_map(
            fn(array $event): array => $this->decorateEvent($event, $eventLogFilter->excludeKeyHashes),
            $this->eventLogRepository->findLatestCollapsedByKey($eventLogFilter, self::EVENTS_PER_KEY, self::ITEMS_PER_PAGE, ($page - 1) * self::ITEMS_PER_PAGE),
        );
        $events = $this->attachMoreEventsCounts($events, $eventLogFilter);

        return [
            'events' => $events,
            'keyFilter' => null,
            'pagination' => $this->buildPagination($page, $pageCount, $this->eventLogRepository->count($eventLogFilter)),
        ];
    }

    /**
     * Every event of a single key, newest first.
     *
     * @return array<string, mixed>
     */
    private function buildKeyFilterData(EventLogFilter $eventLogFilter, int $page): array
    {
        $totalCount = $this->eventLogRepository->count($eventLogFilter);
        $pageCount = max(1, (int)ceil($totalCount / self::ITEMS_PER_PAGE));
        $page = min(max(1, $page), $pageCount);

        $events = array_map(
            fn(array $event): array => $this->decorateEvent($event, $eventLogFilter->excludeKeyHashes),
            $this->eventLogRepository->findLatest($eventLogFilter, self::ITEMS_PER_PAGE, ($page - 1) * self::ITEMS_PER_PAGE),
        );

        return [
            'events' => $events,
            'keyFilter' => [
                'hash' => $eventLogFilter->keyHash,
                'display' => $this->eventLogRepository->findKeyDisplay($eventLogFilter->keyHash),
            ],
            'pagination' => $this->buildPagination($page, $pageCount, $totalCount),
        ];
    }

    /**
     * Chip data for the excluded keys: the readable key form and the
     * exclusion list without the chip's own hash, for the remove link.
     *
     * @param list<string> $excludeKeyHashes
     * @return list<array{hash: string, display: string, remainingHashes: list<string>}>
     */
    private function buildExcludedKeyChips(array $excludeKeyHashes): array
    {
        return array_map(fn(string $excludedHash): array => [
            'hash' => $excludedHash,
            'display' => $this->eventLogRepository->findKeyDisplay($excludedHash),
            'remainingHashes' => array_values(array_diff($excludeKeyHashes, [$excludedHash])),
        ], $excludeKeyHashes);
    }

    /**
     * Whether events older than the retention period, plus one day of grace
     * for the scheduled run, still exist - the signal that the prune command
     * is not running regularly.
     */
    private function isPruneOverdue(): bool
    {
        $cutOff = time() - ($this->eventLogSettings->getRetentionDays() + 1) * 86400;

        return $cutOff > 0 && $this->eventLogRepository->hasEventsOlderThan($cutOff);
    }

    /**
     * Tag list data: each event type present in the log with its active state
     * and the type list a click on the tag switches to. Types without rows
     * (including never-written deprecated ones) are not offered - unless they
     * are currently active: a persisted filter for a since-pruned type must
     * stay visible so it can be toggled off.
     *
     * @param list<string> $currentTypes
     * @return list<array{value: string, active: bool, color: string, toggledTypes: list<string>}>
     */
    private function buildTypeFilters(array $currentTypes): array
    {
        $presentTypes = $this->eventLogRepository->findDistinctEventTypes();
        $offeredTypes = array_values(array_filter(
            FirewallEventType::cases(),
            static fn(FirewallEventType $firewallEventType): bool => in_array($firewallEventType->value, $presentTypes, true)
                || in_array($firewallEventType->value, $currentTypes, true),
        ));

        return array_map(function (FirewallEventType $firewallEventType) use ($currentTypes): array {
            $active = in_array($firewallEventType->value, $currentTypes, true);

            return [
                'value' => $firewallEventType->value,
                'active' => $active,
                'color' => $this->colorForType($firewallEventType->value),
                'toggledTypes' => $active
                    ? array_values(array_diff($currentTypes, [$firewallEventType->value]))
                    : [...$currentTypes, $firewallEventType->value],
            ];
        }, $offeredTypes);
    }

    /**
     * Attach the hidden-event count to each row that hit the per-key cap.
     *
     * @param list<array<string, mixed>> $events
     * @return list<array<string, mixed>>
     */
    private function attachMoreEventsCounts(array $events, EventLogFilter $eventLogFilter): array
    {
        $cappedKeyHashes = [];
        foreach ($events as $event) {
            if (self::isCappedRow($event) && is_string($event['key_hash'])) {
                $cappedKeyHashes[] = $event['key_hash'];
            }
        }

        $totalCounts = $this->eventLogRepository->countByKeyHashes($eventLogFilter, $cappedKeyHashes);

        return array_map(static function (array $event) use ($totalCounts): array {
            $keyHash = is_string($event['key_hash']) ? $event['key_hash'] : '';
            $event['moreEventsCount'] = self::isCappedRow($event)
                ? max(0, ($totalCounts[$keyHash] ?? 0) - self::EVENTS_PER_KEY)
                : 0;

            return $event;
        }, $events);
    }

    /**
     * Whether the row is the last one shown for its key in the collapsed
     * timeline.
     *
     * @param array<string, mixed> $event
     */
    private static function isCappedRow(array $event): bool
    {
        $rowNumber = $event[EventLogRepository::KEY_ROW_NUMBER] ?? null;

        return is_numeric($rowNumber) && (int)$rowNumber === self::EVENTS_PER_KEY;
    }

    /**
     * @param array<string, mixed> $event
     * @param list<string> $excludeKeyHashes
     * @return array<string, mixed>
     */
    private function decorateEvent(array $event, array $excludeKeyHashes): array
    {
        $meta = is_array($event['meta']) ? $event['meta'] : [];
        $event['requestHeaderLines'] = $this->buildRequestHeaderLines($meta);
        unset($meta['requestHeaders']);
        $event['metaLines'] = $this->flattenMeta($this->withoutRedundantOwaspRuleIds($meta));
        $event['typeColor'] = $this->colorForType(is_string($event['event_type']) ? $event['event_type'] : '');

        return $this->decorateKeyActions($event, $excludeKeyHashes);
    }

    /**
     * "Name: value" display lines of the recorded request headers, rendered
     * as their own block instead of meta lines.
     *
     * @param array<string, mixed> $meta
     * @return list<string>
     */
    private function buildRequestHeaderLines(array $meta): array
    {
        $requestHeaders = $meta['requestHeaders'] ?? null;
        if (!is_array($requestHeaders)) {
            return [];
        }

        $lines = [];
        foreach ($requestHeaders as $name => $value) {
            if (is_string($name) && is_scalar($value)) {
                $lines[] = $name . ': ' . $value;
            }
        }

        return $lines;
    }

    /**
     * Drop the matched-rule list when it only repeats the single primary
     * rule id, so the details do not show the same value twice. With
     * several matched rules both stay: the list is the full picture, the
     * primary id is the rule the msg and matched-variable lines belong to.
     *
     * @param array<string, mixed> $meta
     * @return array<string, mixed>
     */
    private function withoutRedundantOwaspRuleIds(array $meta): array
    {
        $matchedRuleIds = $meta['owasp_rule_ids'] ?? null;
        $primaryRuleId = $meta['owasp_rule_id'] ?? null;
        if (is_scalar($matchedRuleIds) && is_scalar($primaryRuleId) && (string)$matchedRuleIds === (string)$primaryRuleId) {
            unset($meta['owasp_rule_ids']);
        }

        return $meta;
    }

    /**
     * Attach the current block status of the row's key, the exclusion list a
     * "hide this key" link switches to, and, for keys that still carry the
     * full readable IP and are not blocked yet, the offered block action.
     *
     * @param array<string, mixed> $event
     * @param list<string> $excludeKeyHashes
     * @return array<string, mixed>
     */
    private function decorateKeyActions(array $event, array $excludeKeyHashes): array
    {
        $keyHash = is_string($event['key_hash']) ? $event['key_hash'] : '';
        $keyDisplay = is_string($event['key_display']) ? $event['key_display'] : '';

        $event['excludeKeysWithSelf'] = $keyHash === '' ? $excludeKeyHashes : [...$excludeKeyHashes, $keyHash];

        $event['blockStatus'] = $keyHash === ''
            ? null
            : $this->keyBlockStatusProvider->findBlockStatus($keyHash, $keyDisplay);
        $event['blockAction'] = null;
        $event['blockValue'] = '';

        if ($event['blockStatus'] instanceof KeyBlockStatus) {
            return $event;
        }

        $blockEntry = $this->blockableKeyResolver->resolve($keyDisplay);
        if ($blockEntry instanceof PatternEntry) {
            $event['blockAction'] = 'ip';
            $event['blockValue'] = $blockEntry->value;
        }

        return $event;
    }

    /**
     * The chart palette color of the event type, with a neutral fallback for
     * types the chart does not show.
     */
    private function colorForType(string $eventType): string
    {
        return $this->barChartBuilder->colorForType($eventType) ?? self::NEUTRAL_TYPE_COLOR;
    }

    /**
     * @return array<string, int|bool>
     */
    private function buildPagination(int $page, int $pageCount, int $totalCount): array
    {
        return [
            'currentPage' => $page,
            'pageCount' => $pageCount,
            'totalCount' => $totalCount,
            'hasPrevious' => $page > 1,
            'hasNext' => $page < $pageCount,
            'previousPage' => max(1, $page - 1),
            'nextPage' => min($pageCount, $page + 1),
        ];
    }

    /**
     * Keep only known event type values, without duplicates.
     *
     * @param array<mixed> $types
     * @return list<string>
     */
    private function sanitizeTypes(array $types): array
    {
        $sanitized = [];
        foreach ($types as $type) {
            if (is_string($type) && FirewallEventType::tryFrom($type) instanceof FirewallEventType && !in_array($type, $sanitized, true)) {
                $sanitized[] = $type;
            }
        }

        return $sanitized;
    }

    /**
     * Flatten a decoded meta array into "key: value" display lines; nested keys
     * are joined with a dot (e.g. "diagnosticHeaders.X-Phirewall-Owasp-Rule: 942100").
     *
     * @param array<mixed> $meta
     * @return list<string>
     */
    private function flattenMeta(array $meta, string $prefix = ''): array
    {
        $lines = [];
        foreach ($meta as $key => $value) {
            $label = $prefix === '' ? (string)$key : $prefix . '.' . $key;
            if (is_array($value)) {
                $lines = [...$lines, ...$this->flattenMeta($value, $label)];
                continue;
            }

            $lines[] = $label . ': ' . (is_scalar($value) ? (string)$value : (string)json_encode($value));
        }

        return $lines;
    }
}
