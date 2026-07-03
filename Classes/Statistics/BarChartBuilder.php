<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Statistics;

use Flowd\Typo3Firewall\EventLog\FirewallEventType;

/**
 * Computes the geometry of the statistics bar chart so the Fluid template
 * only renders ready-made SVG coordinates.
 *
 * Buckets are stacked bars with one segment per event type. Each type keeps
 * its color no matter which types are present, so a type is always shown in
 * the same color across ranges.
 */
final class BarChartBuilder
{
    private const int WIDTH = 720;

    private const int HEIGHT = 220;

    private const int PLOT_TOP = 16;

    private const int PLOT_BOTTOM = 196;

    private const int PLOT_LEFT = 8;

    private const int PLOT_RIGHT = 712;

    private const int BAR_GAP = 2;

    private const int SEGMENT_GAP = 2;

    private const int TICK_TARGET_COUNT = 6;

    /**
     * Stack order (bottom to top) and color per event type. The palette is
     * colorblind-safe in this order; keep it fixed when adding types.
     */
    private const array TYPE_COLORS = [
        FirewallEventType::BlocklistMatched->value => '#2a78d6',
        FirewallEventType::ThrottleExceeded->value => '#1baf7a',
        FirewallEventType::Fail2BanBanned->value => '#eda100',
        FirewallEventType::Allow2BanBanned->value => '#008300',
    ];

    /**
     * @param array<int, array<string, int>> $bucketTypeCounts bucket start timestamp => event type => count
     * @return array{
     *     width: int,
     *     height: int,
     *     baselineY: int,
     *     maxCount: int,
     *     totalCount: int,
     *     bars: list<array{x: float, width: float, count: int, label: string, showValue: bool, valueX: float, valueY: float, segments: list<array{y: float, height: float, count: int, type: string, color: string, rx: int}>}>,
     *     legend: list<array{type: string, color: string, count: int}>,
     *     ticks: list<array{x: float, label: string}>
     * }
     */
    public function build(array $bucketTypeCounts, int $since, int $until, int $bucketSeconds, string $labelFormat): array
    {
        $bucketStarts = $this->computeBucketStarts($since, $until, $bucketSeconds);
        $totals = array_map(
            static fn(int $bucketStart): int => array_sum($bucketTypeCounts[$bucketStart] ?? []),
            $bucketStarts
        );
        $maxCount = $totals === [] ? 0 : max($totals);

        $bucketCount = count($bucketStarts);
        $plotWidth = self::PLOT_RIGHT - self::PLOT_LEFT;
        $slotWidth = $bucketCount > 0 ? $plotWidth / $bucketCount : $plotWidth;
        $barWidth = max(1.0, $slotWidth - self::BAR_GAP);
        $tickInterval = max(1, (int)ceil($bucketCount / self::TICK_TARGET_COUNT));

        $bars = [];
        $ticks = [];
        foreach ($bucketStarts as $index => $bucketStart) {
            $x = self::PLOT_LEFT + $index * $slotWidth + self::BAR_GAP / 2;
            $label = date($labelFormat, $bucketStart);
            $bars[] = $this->buildBar($x, $barWidth, $bucketTypeCounts[$bucketStart] ?? [], $totals[$index], $maxCount, $label);

            if ($index % $tickInterval === 0) {
                $ticks[] = [
                    'x' => round($x + $barWidth / 2, 1),
                    'label' => $label,
                ];
            }
        }

        return [
            'width' => self::WIDTH,
            'height' => self::HEIGHT,
            'baselineY' => self::PLOT_BOTTOM,
            'maxCount' => $maxCount,
            'totalCount' => array_sum($totals),
            'bars' => $bars,
            'legend' => $this->buildLegend($bucketTypeCounts),
            'ticks' => $ticks,
        ];
    }

    /**
     * @return list<int>
     */
    private function computeBucketStarts(int $since, int $until, int $bucketSeconds): array
    {
        $bucketStarts = [];
        for ($bucketStart = $since - ($since % $bucketSeconds); $bucketStart <= $until; $bucketStart += $bucketSeconds) {
            $bucketStarts[] = $bucketStart;
        }

        return $bucketStarts;
    }

    /**
     * @param array<string, int> $typeCounts
     * @return array{x: float, width: float, count: int, label: string, showValue: bool, valueX: float, valueY: float, segments: list<array{y: float, height: float, count: int, type: string, color: string, rx: int}>}
     */
    private function buildBar(float $x, float $barWidth, array $typeCounts, int $total, int $maxCount, string $label): array
    {
        $plotHeight = self::PLOT_BOTTOM - self::PLOT_TOP;
        $barHeight = $maxCount > 0 ? ($total / $maxCount) * $plotHeight : 0.0;
        if ($total > 0) {
            $barHeight = max(2.0, $barHeight);
        }

        return [
            'x' => round($x, 1),
            'width' => round($barWidth, 1),
            'count' => $total,
            'label' => $label,
            'showValue' => $total > 0 && $total === $maxCount,
            'valueX' => round($x + $barWidth / 2, 1),
            'valueY' => round(self::PLOT_BOTTOM - $barHeight - 5, 1),
            'segments' => $this->buildSegments($typeCounts, $total, $barHeight),
        ];
    }

    /**
     * Stacks the type segments bottom to top. A small gap separates the
     * segments; it is cut from the top of the lower segment so the top edge
     * of the bar stays exact.
     *
     * @param array<string, int> $typeCounts
     * @return list<array{y: float, height: float, count: int, type: string, color: string, rx: int}>
     */
    private function buildSegments(array $typeCounts, int $total, float $barHeight): array
    {
        if ($total <= 0) {
            return [];
        }

        $stack = $this->computeStack($typeCounts, $total, $barHeight);
        $segments = [];
        $topIndex = count($stack) - 1;
        foreach ($stack as $index => $stackEntry) {
            $isTopSegment = $index === $topIndex;
            $gap = !$isTopSegment && self::SEGMENT_GAP + 1 < $stackEntry['bottom'] - $stackEntry['top'] ? self::SEGMENT_GAP : 0;
            $segments[] = [
                'y' => round($stackEntry['top'] + $gap, 1),
                'height' => round($stackEntry['bottom'] - $stackEntry['top'] - $gap, 1),
                'count' => $stackEntry['count'],
                'type' => $stackEntry['type'],
                'color' => $stackEntry['color'],
                'rx' => $isTopSegment ? 2 : 0,
            ];
        }

        return $segments;
    }

    /**
     * Raw stack geometry per present type, bottom to top.
     *
     * @param array<string, int> $typeCounts
     * @return list<array{type: string, color: string, count: int, top: float, bottom: float}>
     */
    private function computeStack(array $typeCounts, int $total, float $barHeight): array
    {
        $stack = [];
        $cumulativeHeight = 0.0;
        foreach (self::TYPE_COLORS as $type => $color) {
            $count = $typeCounts[$type] ?? 0;
            if ($count <= 0) {
                continue;
            }

            $segmentBottom = self::PLOT_BOTTOM - $cumulativeHeight;
            $cumulativeHeight += ($count / $total) * $barHeight;
            $stack[] = [
                'type' => $type,
                'color' => $color,
                'count' => $count,
                'top' => self::PLOT_BOTTOM - $cumulativeHeight,
                'bottom' => $segmentBottom,
            ];
        }

        return $stack;
    }

    /**
     * Legend entries for the types present in the data, in stack order.
     *
     * @param array<int, array<string, int>> $bucketTypeCounts
     * @return list<array{type: string, color: string, count: int}>
     */
    private function buildLegend(array $bucketTypeCounts): array
    {
        $typeTotals = [];
        foreach ($bucketTypeCounts as $bucketTypeCount) {
            foreach ($bucketTypeCount as $type => $count) {
                $typeTotals[$type] = ($typeTotals[$type] ?? 0) + $count;
            }
        }

        $legend = [];
        foreach (self::TYPE_COLORS as $type => $color) {
            if (($typeTotals[$type] ?? 0) > 0) {
                $legend[] = ['type' => $type, 'color' => $color, 'count' => $typeTotals[$type]];
            }
        }

        return $legend;
    }
}
