<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Statistics;

use Flowd\Typo3Firewall\EventLog\EventLogSettings;

/**
 * Assembles the view data for the statistics module view.
 */
final class StatisticsViewDataProvider
{
    private const string DEFAULT_RANGE = '24h';

    private const int RECENT_EVENTS_LIMIT = 20;

    private const int EVENTS_PER_KEY = 3;

    /**
     * @var array<string, array{window: int, bucket: int, labelFormat: string}>
     */
    private const array RANGES = [
        '24h' => ['window' => 86400, 'bucket' => 3600, 'labelFormat' => 'H:00'],
        '7d' => ['window' => 604800, 'bucket' => 86400, 'labelFormat' => 'd.m.'],
        '30d' => ['window' => 2592000, 'bucket' => 86400, 'labelFormat' => 'd.m.'],
    ];

    public function __construct(
        private readonly EventStatisticsRepository $eventStatisticsRepository,
        private readonly BarChartBuilder $barChartBuilder,
        private readonly EventLogSettings $eventLogSettings,
    ) {}

    /**
     * View variables for the given time range; unknown ranges fall back to the default.
     *
     * @return array<string, mixed>
     */
    public function getViewData(string $range): array
    {
        if (!isset(self::RANGES[$range])) {
            $range = self::DEFAULT_RANGE;
        }

        $rangeConfiguration = self::RANGES[$range];
        $now = time();
        $since = $now - $rangeConfiguration['window'];
        $startOfToday = (new \DateTimeImmutable('today'))->getTimestamp();

        $chart = $this->barChartBuilder->build(
            $this->eventStatisticsRepository->countBlockingEventsPerBucketAndType($since, $rangeConfiguration['bucket']),
            $since,
            $now,
            $rangeConfiguration['bucket'],
            $rangeConfiguration['labelFormat']
        );

        $typeCounts = [];
        foreach ($this->eventStatisticsRepository->countEventsByTypeSince($since) as $eventType => $count) {
            $typeCounts[] = ['type' => $eventType, 'count' => $count];
        }

        return [
            'blockedToday' => $this->eventStatisticsRepository->countDistinctBlockedKeysSince($startOfToday),
            'chart' => $chart,
            'typeCounts' => $typeCounts,
            'topRules' => $this->eventStatisticsRepository->findTopRulesSince($since),
            'topPaths' => $this->eventStatisticsRepository->findTopPathsSince($since),
            'recentEvents' => $this->buildRecentEvents($since),
            'range' => $range,
            'ranges' => array_keys(self::RANGES),
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
        ];
    }

    /**
     * The latest blocking events with the color of their type in the chart.
     * Each key is collapsed to its newest three events; the last visible row
     * of a collapsed key carries the number of hidden events in moreCount.
     *
     * @return list<array{createdAt: int, eventType: string, rule: string, requestMethod: string, requestPath: string, keyDisplay: string, keyHash: string, keyRowNumber: int, color: ?string, moreCount: int}>
     */
    private function buildRecentEvents(int $since): array
    {
        $recentEvents = $this->eventStatisticsRepository->findRecentBlockingEvents($since, self::RECENT_EVENTS_LIMIT, self::EVENTS_PER_KEY);

        $cappedKeyHashes = [];
        foreach ($recentEvents as $recentEvent) {
            if ($recentEvent['keyRowNumber'] === self::EVENTS_PER_KEY && $recentEvent['keyHash'] !== '') {
                $cappedKeyHashes[] = $recentEvent['keyHash'];
            }
        }

        $totalCounts = $this->eventStatisticsRepository->countBlockingEventsPerKeySince($since, $cappedKeyHashes);

        return array_map(
            fn(array $recentEvent): array => $recentEvent + [
                'color' => $this->barChartBuilder->colorForType($recentEvent['eventType']),
                'moreCount' => $recentEvent['keyRowNumber'] === self::EVENTS_PER_KEY
                    ? max(0, ($totalCounts[$recentEvent['keyHash']] ?? 0) - self::EVENTS_PER_KEY)
                    : 0,
            ],
            $recentEvents
        );
    }
}
