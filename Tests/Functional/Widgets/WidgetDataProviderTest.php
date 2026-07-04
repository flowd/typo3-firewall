<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Widgets;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\Widgets\Provider\BlockedTodayDataProvider;
use Flowd\Typo3Firewall\Widgets\Provider\FirewallEventsChartDataProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(FirewallEventsChartDataProvider::class)]
#[CoversClass(BlockedTodayDataProvider::class)]
final class WidgetDataProviderTest extends FunctionalTestCase
{
    protected array $coreExtensionsToLoad = [
        'typo3/cms-dashboard',
    ];

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->create('default');
    }

    #[Test]
    public function chartDataCoversTheLastSevenDays(): void
    {
        // A timezone with an offset ensures local days differ from the epoch aligned SQL buckets.
        $previousTimezone = date_default_timezone_get();
        date_default_timezone_set('Europe/Berlin');

        try {
            $startOfToday = new \DateTimeImmutable('today');
            $this->insertEvent('hash-a', $startOfToday->getTimestamp() + 60);
            $this->insertEvent('hash-b', $startOfToday->getTimestamp() + 120);
            $this->insertEvent('hash-c', $startOfToday->modify('-2 days')->getTimestamp() + 60);

            $chartData = $this->get(FirewallEventsChartDataProvider::class)->getChartData();

            self::assertCount(7, $chartData['labels']);
            self::assertCount(7, $chartData['datasets'][0]['data']);
            self::assertSame(2, $chartData['datasets'][0]['data'][6]);
            self::assertSame(1, $chartData['datasets'][0]['data'][4]);
            self::assertSame(3, array_sum($chartData['datasets'][0]['data']));
        } finally {
            date_default_timezone_set($previousTimezone);
        }
    }

    #[Test]
    public function chartDataAttributesMidnightEventsToTheCorrectLocalDay(): void
    {
        // Kathmandu is offset by 5:45, so local midnight sits inside an hour bucket.
        $previousTimezone = date_default_timezone_get();
        date_default_timezone_set('Asia/Kathmandu');

        try {
            $startOfToday = (new \DateTimeImmutable('today'))->getTimestamp();
            $this->insertEvent('hash-after-midnight', $startOfToday + 60);
            $this->insertEvent('hash-before-midnight', $startOfToday - 60);

            $chartData = $this->get(FirewallEventsChartDataProvider::class)->getChartData();

            self::assertSame(1, $chartData['datasets'][0]['data'][6]);
            self::assertSame(1, $chartData['datasets'][0]['data'][5]);
        } finally {
            date_default_timezone_set($previousTimezone);
        }
    }

    #[Test]
    public function blockedTodayCountsDistinctClientsSinceMidnight(): void
    {
        $startOfToday = (new \DateTimeImmutable('today'))->getTimestamp();
        $this->insertEvent('hash-a', $startOfToday + 60);
        $this->insertEvent('hash-a', $startOfToday + 120);
        $this->insertEvent('hash-b', $startOfToday + 180);
        $this->insertEvent('hash-yesterday', $startOfToday - 3600);

        self::assertSame(2, $this->get(BlockedTodayDataProvider::class)->getNumber());
    }

    private function insertEvent(string $keyHash, int $createdAt): void
    {
        $this->getConnectionPool()->getConnectionForTable(EventLogger::TABLE_NAME)->insert(EventLogger::TABLE_NAME, [
            'event_type' => 'blocklist_matched',
            'rule' => 'scanner-paths',
            'key_hash' => $keyHash,
            'created_at' => $createdAt,
        ]);
    }
}
