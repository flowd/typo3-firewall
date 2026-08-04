<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Statistics;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\Statistics\StatisticsViewDataProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(StatisticsViewDataProvider::class)]
final class StatisticsViewDataProviderTest extends FunctionalTestCase
{
    private const string KEY_HASH_FLOODER = 'hash-flooder';

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    private StatisticsViewDataProvider $statisticsViewDataProvider;

    protected function setUp(): void
    {
        parent::setUp();
        $this->statisticsViewDataProvider = $this->get(StatisticsViewDataProvider::class);
    }

    #[Test]
    public function getViewDataCollapsesRecentEventsAndCountsTheHiddenOnes(): void
    {
        $this->insertFlooderEvents(5);

        $recentEvents = $this->statisticsViewDataProvider->getViewData('24h')['recentEvents'];
        self::assertIsArray($recentEvents);

        self::assertSame(['flood-rule-4', 'flood-rule-3', 'flood-rule-2'], array_column($recentEvents, 'rule'));
        self::assertSame([0, 0, 2], array_column($recentEvents, 'moreCount'));
    }

    #[Test]
    public function getViewDataDoesNotFlagMoreEventsForAKeyWithExactlyThreeEvents(): void
    {
        $this->insertFlooderEvents(3);

        $recentEvents = $this->statisticsViewDataProvider->getViewData('24h')['recentEvents'];
        self::assertIsArray($recentEvents);

        self::assertSame(['flood-rule-2', 'flood-rule-1', 'flood-rule-0'], array_column($recentEvents, 'rule'));
        self::assertSame([0, 0, 0], array_column($recentEvents, 'moreCount'));
    }

    private function insertFlooderEvents(int $count): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(EventLogger::TABLE_NAME);
        $now = time();
        for ($i = 0; $i < $count; ++$i) {
            $connection->insert(EventLogger::TABLE_NAME, [
                'event_type' => 'throttle_exceeded',
                'rule' => 'flood-rule-' . $i,
                'key_hash' => self::KEY_HASH_FLOODER,
                'key_display' => '203.0.113.0',
                'request_path' => '/search',
                'request_method' => 'GET',
                'created_at' => $now - $count + $i,
            ]);
        }
    }
}
