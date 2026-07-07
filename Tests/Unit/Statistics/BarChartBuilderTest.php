<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Statistics;

use Flowd\Typo3Firewall\Statistics\BarChartBuilder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(BarChartBuilder::class)]
final class BarChartBuilderTest extends TestCase
{
    #[Test]
    public function emptyDataProducesBarsWithoutSegments(): void
    {
        $chart = (new BarChartBuilder())->build([], 0, 3 * 3600, 3600, 'H:00');

        self::assertSame(0, $chart['maxCount']);
        self::assertSame(0, $chart['totalCount']);
        self::assertSame([], $chart['legend']);
        self::assertCount(4, $chart['bars']);
        foreach ($chart['bars'] as $bar) {
            self::assertSame([], $bar['segments']);
            self::assertFalse($bar['showValue']);
        }
    }

    #[Test]
    public function missingBucketsAreFilledWithZero(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 5], 7200 => ['blocklist_matched' => 10]],
            0,
            3 * 3600,
            3600,
            'H:00'
        );

        self::assertSame([5, 0, 10, 0], array_column($chart['bars'], 'count'));
        self::assertSame(15, $chart['totalCount']);
        self::assertSame(10, $chart['maxCount']);
    }

    #[Test]
    public function barHeightsScaleAgainstTheMaximum(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 5], 3600 => ['blocklist_matched' => 10]],
            0,
            3600,
            3600,
            'H:00'
        );

        $fullHeightSegment = $chart['bars'][1]['segments'][0];
        $halfHeightSegment = $chart['bars'][0]['segments'][0];
        self::assertGreaterThan(0, $halfHeightSegment['height']);
        self::assertEqualsWithDelta($fullHeightSegment['height'] / 2, $halfHeightSegment['height'], 0.2);
        self::assertSame($chart['baselineY'] - $fullHeightSegment['height'], $fullHeightSegment['y']);
    }

    #[Test]
    public function segmentsStackBottomUpInFixedTypeOrder(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['fail2ban_banned' => 25, 'blocklist_matched' => 50, 'throttle_exceeded' => 25, 'fail2ban_matched' => 25]],
            0,
            0,
            3600,
            'H:00'
        );

        $segments = $chart['bars'][0]['segments'];
        self::assertSame(
            ['blocklist_matched', 'throttle_exceeded', 'fail2ban_matched', 'fail2ban_banned'],
            array_column($segments, 'type')
        );
        self::assertGreaterThan($segments[1]['y'], $segments[0]['y']);
        self::assertGreaterThan($segments[2]['y'], $segments[1]['y']);
        self::assertGreaterThan($segments[3]['y'], $segments[2]['y']);
        self::assertEqualsWithDelta($chart['baselineY'], $segments[0]['y'] + $segments[0]['height'], 0.11);
    }

    #[Test]
    public function everyTypeKeepsItsColorRegardlessOfPresentTypes(): void
    {
        $barChartBuilder = new BarChartBuilder();
        $allTypes = $barChartBuilder->build(
            [0 => ['blocklist_matched' => 1, 'throttle_exceeded' => 1, 'fail2ban_matched' => 1, 'fail2ban_banned' => 1, 'allow2ban_banned' => 1]],
            0,
            0,
            3600,
            'H:00'
        );
        $onlyFail2Ban = $barChartBuilder->build([0 => ['fail2ban_banned' => 3]], 0, 0, 3600, 'H:00');

        $colorsByType = array_column($allTypes['bars'][0]['segments'], 'color', 'type');
        self::assertCount(5, array_unique($colorsByType));
        self::assertSame($colorsByType['fail2ban_banned'], $onlyFail2Ban['bars'][0]['segments'][0]['color']);
    }

    #[Test]
    public function onlyTheTopSegmentHasRoundedCorners(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 50, 'fail2ban_banned' => 50]],
            0,
            0,
            3600,
            'H:00'
        );

        self::assertSame([0, 2], array_column($chart['bars'][0]['segments'], 'rx'));
    }

    #[Test]
    public function aGapSeparatesStackedSegments(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 50, 'fail2ban_banned' => 50]],
            0,
            0,
            3600,
            'H:00'
        );

        [$lowerSegment, $upperSegment] = $chart['bars'][0]['segments'];
        self::assertSame(2.0, round($lowerSegment['y'] - ($upperSegment['y'] + $upperSegment['height']), 1));
    }

    #[Test]
    public function legendListsOnlyPresentTypesInStackOrder(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['fail2ban_banned' => 3], 3600 => ['blocklist_matched' => 7]],
            0,
            3600,
            3600,
            'H:00'
        );

        self::assertSame(['blocklist_matched', 'fail2ban_banned'], array_column($chart['legend'], 'type'));
        self::assertSame([7, 3], array_column($chart['legend'], 'count'));
    }

    #[Test]
    public function onlyTheMaximumBarShowsItsValue(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 5], 3600 => ['blocklist_matched' => 10], 7200 => ['blocklist_matched' => 3]],
            0,
            2 * 3600,
            3600,
            'H:00'
        );

        self::assertSame([false, true, false], array_column($chart['bars'], 'showValue'));
    }

    #[Test]
    public function smallCountsGetAMinimumVisibleHeight(): void
    {
        $chart = (new BarChartBuilder())->build(
            [0 => ['blocklist_matched' => 1], 3600 => ['blocklist_matched' => 1000]],
            0,
            3600,
            3600,
            'H:00'
        );

        self::assertGreaterThanOrEqual(2.0, $chart['bars'][0]['segments'][0]['height']);
    }

    #[Test]
    public function ticksAreEmittedAtRegularIntervals(): void
    {
        $chart = (new BarChartBuilder())->build([], 0, 23 * 3600, 3600, 'H:00');

        self::assertCount(6, $chart['ticks']);
        self::assertSame('00:00', $chart['ticks'][0]['label']);
    }
}
