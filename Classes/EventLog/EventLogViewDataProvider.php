<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

/**
 * Assembles the view data for the event log module view.
 */
final class EventLogViewDataProvider
{
    private const int EVENT_LIST_LIMIT = 100;

    public function __construct(
        private readonly EventLogRepository $eventLogRepository,
        private readonly EventLogSettings $eventLogSettings,
    ) {}

    /**
     * View variables for the event log view; unknown types fall back to all types.
     *
     * @return array<string, mixed>
     */
    public function getViewData(string $type, string $search): array
    {
        $eventType = FirewallEventType::tryFrom($type);
        $currentType = $eventType instanceof FirewallEventType ? $eventType->value : '';

        $events = array_map(function (array $event): array {
            $event['metaLines'] = $this->flattenMeta(is_array($event['meta']) ? $event['meta'] : []);
            return $event;
        }, $this->eventLogRepository->findLatest($currentType, $search, self::EVENT_LIST_LIMIT));

        return [
            'events' => $events,
            'eventTypes' => FirewallEventType::cases(),
            'currentType' => $currentType,
            'search' => $search,
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
            'limit' => self::EVENT_LIST_LIMIT,
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
