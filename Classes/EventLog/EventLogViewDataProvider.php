<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

/**
 * Assembles the view data for the event log module view.
 */
final class EventLogViewDataProvider
{
    private const int ITEMS_PER_PAGE = 50;

    public function __construct(
        private readonly EventLogRepository $eventLogRepository,
        private readonly EventLogSettings $eventLogSettings,
    ) {}

    /**
     * View variables for the event log view; unknown types fall back to all
     * types, out-of-range pages are clamped.
     *
     * @return array<string, mixed>
     */
    public function getViewData(string $type, string $search, int $page = 1): array
    {
        $eventType = FirewallEventType::tryFrom($type);
        $currentType = $eventType instanceof FirewallEventType ? $eventType->value : '';

        $totalCount = $this->eventLogRepository->count($currentType, $search);
        $pageCount = max(1, (int)ceil($totalCount / self::ITEMS_PER_PAGE));
        $page = min(max(1, $page), $pageCount);

        $events = array_map(function (array $event): array {
            $event['metaLines'] = $this->flattenMeta(is_array($event['meta']) ? $event['meta'] : []);
            return $event;
        }, $this->eventLogRepository->findLatest($currentType, $search, self::ITEMS_PER_PAGE, ($page - 1) * self::ITEMS_PER_PAGE));

        return [
            'events' => $events,
            'eventTypes' => FirewallEventType::cases(),
            'currentType' => $currentType,
            'search' => $search,
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
            'pagination' => [
                'currentPage' => $page,
                'pageCount' => $pageCount,
                'totalCount' => $totalCount,
                'hasPrevious' => $page > 1,
                'hasNext' => $page < $pageCount,
                'previousPage' => max(1, $page - 1),
                'nextPage' => min($pageCount, $page + 1),
            ],
        ];
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
