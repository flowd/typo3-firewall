<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Widgets\Provider;

use Flowd\Typo3Firewall\Statistics\EventStatisticsRepository;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Dashboard\Widgets\ChartDataProviderInterface;

/**
 * Chart data for the "Firewall events" dashboard widget: blocked
 * requests per day over the last seven days.
 */
final class FirewallEventsChartDataProvider implements ChartDataProviderInterface
{
    private const int DAYS = 7;

    public function __construct(
        private readonly EventStatisticsRepository $eventStatisticsRepository,
    ) {}

    /**
     * @return array{labels: list<string>, datasets: list<array{label: string, backgroundColor: string, border: int, data: list<int>}>}
     */
    public function getChartData(): array
    {
        $startOfToday = new \DateTimeImmutable('today');
        $firstDay = $startOfToday->modify(sprintf('-%d days', self::DAYS - 1));

        // The SQL buckets are aligned to the Unix epoch (UTC). Minute buckets are
        // summed into local days here, so the chart shows local calendar days:
        // every current UTC offset is a whole number of minutes, so each local
        // midnight sits exactly on the bucket grid.
        $minuteBuckets = $this->eventStatisticsRepository->countBlockingEventsPerBucketAndType($firstDay->getTimestamp(), 60);

        $labels = [];
        $data = [];
        for ($day = $firstDay; $day <= $startOfToday; $day = $day->modify('+1 day')) {
            $labels[] = $day->format('d.m.');
            $data[] = $this->sumBucketsBetween($minuteBuckets, $day->getTimestamp(), $day->modify('+1 day')->getTimestamp());
        }

        return [
            'labels' => $labels,
            'datasets' => [
                [
                    'label' => $this->getLanguageService()->sL('LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.events.dataset'),
                    'backgroundColor' => '#0078e6',
                    'border' => 0,
                    'data' => $data,
                ],
            ],
        ];
    }

    /**
     * @param array<int, array<string, int>> $buckets
     */
    private function sumBucketsBetween(array $buckets, int $from, int $until): int
    {
        $sum = 0;
        foreach ($buckets as $bucketStart => $typeCounts) {
            if ($bucketStart >= $from && $bucketStart < $until) {
                $sum += array_sum($typeCounts);
            }
        }

        return $sum;
    }

    private function getLanguageService(): LanguageService
    {
        /** @var LanguageService $languageService */
        $languageService = $GLOBALS['LANG'];
        return $languageService;
    }
}
