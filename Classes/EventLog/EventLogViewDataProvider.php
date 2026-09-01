<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

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
    private const int ITEMS_PER_PAGE = 50;

    private const int EVENTS_PER_KEY = 3;

    /** Dot and tag color for event types outside the chart palette. */
    private const string NEUTRAL_TYPE_COLOR = '#6b7280';

    public function __construct(
        private readonly EventLogRepository $eventLogRepository,
        private readonly EventLogSettings $eventLogSettings,
        private readonly BarChartBuilder $barChartBuilder,
    ) {}

    /**
     * View variables for the event log view; unknown types and malformed key
     * hashes fall back to the unfiltered view, out-of-range pages are clamped.
     *
     * @param array<mixed> $types
     * @return array<string, mixed>
     */
    public function getViewData(array $types, string $search, string $keyHash, string $rule = '', int $page = 1): array
    {
        $currentTypes = $this->sanitizeTypes($types);
        $keyHash = preg_match('/^[a-f0-9]{64}$/', $keyHash) === 1 ? $keyHash : '';
        $rule = mb_substr(trim($rule), 0, 255);

        $viewData = $keyHash === ''
            ? $this->buildCollapsedTimelineData($currentTypes, $search, $rule, $page)
            : $this->buildKeyFilterData($currentTypes, $search, $keyHash, $rule, $page);

        return [
            ...$viewData,
            'typeFilters' => $this->buildTypeFilters($currentTypes),
            'currentTypes' => $currentTypes,
            'search' => $search,
            'ruleFilter' => $rule === '' ? null : $rule,
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
        ];
    }

    /**
     * Timeline with at most three events per key; rows hitting that cap carry
     * a moreEventsCount with the number of older events hidden behind the key
     * filter link.
     *
     * @param list<string> $currentTypes
     * @return array<string, mixed>
     */
    private function buildCollapsedTimelineData(array $currentTypes, string $search, string $rule, int $page): array
    {
        // The window ranking sorts every matching row, so bound it to the
        // retention period; older rows are awaiting the prune run anyway.
        $since = max(0, time() - $this->eventLogSettings->getRetentionDays() * 86400);

        $rowCount = $this->eventLogRepository->countCollapsedByKey($currentTypes, $search, self::EVENTS_PER_KEY, $since, $rule);
        $pageCount = max(1, (int)ceil($rowCount / self::ITEMS_PER_PAGE));
        $page = min(max(1, $page), $pageCount);

        $events = array_map(
            $this->decorateEvent(...),
            $this->eventLogRepository->findLatestCollapsedByKey($currentTypes, $search, self::EVENTS_PER_KEY, self::ITEMS_PER_PAGE, ($page - 1) * self::ITEMS_PER_PAGE, $since, $rule),
        );
        $events = $this->attachMoreEventsCounts($events, $currentTypes, $search, $since, $rule);

        return [
            'events' => $events,
            'keyFilter' => null,
            'pagination' => $this->buildPagination($page, $pageCount, $this->eventLogRepository->count($currentTypes, $search, '', $since, $rule)),
        ];
    }

    /**
     * Every event of a single key, newest first.
     *
     * @param list<string> $currentTypes
     * @return array<string, mixed>
     */
    private function buildKeyFilterData(array $currentTypes, string $search, string $keyHash, string $rule, int $page): array
    {
        $totalCount = $this->eventLogRepository->count($currentTypes, $search, $keyHash, 0, $rule);
        $pageCount = max(1, (int)ceil($totalCount / self::ITEMS_PER_PAGE));
        $page = min(max(1, $page), $pageCount);

        $events = array_map(
            $this->decorateEvent(...),
            $this->eventLogRepository->findLatest($currentTypes, $search, $keyHash, self::ITEMS_PER_PAGE, ($page - 1) * self::ITEMS_PER_PAGE, $rule),
        );

        return [
            'events' => $events,
            'keyFilter' => [
                'hash' => $keyHash,
                'display' => $this->eventLogRepository->findKeyDisplay($keyHash),
            ],
            'pagination' => $this->buildPagination($page, $pageCount, $totalCount),
        ];
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
     * @param list<string> $currentTypes
     * @return list<array<string, mixed>>
     */
    private function attachMoreEventsCounts(array $events, array $currentTypes, string $search, int $since, string $rule): array
    {
        $cappedKeyHashes = [];
        foreach ($events as $event) {
            if (self::isCappedRow($event) && is_string($event['key_hash'])) {
                $cappedKeyHashes[] = $event['key_hash'];
            }
        }

        $totalCounts = $this->eventLogRepository->countByKeyHashes($currentTypes, $search, $cappedKeyHashes, $since, $rule);

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
     * @return array<string, mixed>
     */
    private function decorateEvent(array $event): array
    {
        $event['metaLines'] = $this->flattenMeta(is_array($event['meta']) ? $event['meta'] : []);
        $event['typeColor'] = $this->colorForType(is_string($event['event_type']) ? $event['event_type'] : '');

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
