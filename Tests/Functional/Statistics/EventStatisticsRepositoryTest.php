<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Statistics;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\Statistics\EventStatisticsRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(EventStatisticsRepository::class)]
final class EventStatisticsRepositoryTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    #[Test]
    public function countDistinctBlockedKeysCountsEveryClientOnce(): void
    {
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-a', 1000);
        $this->insertEvent('fail2ban_banned', 'login-protection', 'hash-a', 1100);
        $this->insertEvent('throttle_exceeded', 'search-throttle', 'hash-b', 1200);
        $this->insertEvent('safelist_matched', 'office-ips', 'hash-c', 1300);
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-old', 10);

        $repository = $this->get(EventStatisticsRepository::class);

        self::assertSame(2, $repository->countDistinctBlockedKeysSince(1000));
    }

    #[Test]
    public function blockingEventsAreGroupedIntoTimeBucketsAndTypes(): void
    {
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-a', 3600);
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-b', 3700);
        $this->insertEvent('fail2ban_banned', 'login-protection', 'hash-b', 3800);
        $this->insertEvent('throttle_exceeded', 'search-throttle', 'hash-c', 7300);
        $this->insertEvent('safelist_matched', 'office-ips', 'hash-d', 7400);

        $repository = $this->get(EventStatisticsRepository::class);

        self::assertSame(
            [
                3600 => ['blocklist_matched' => 2, 'fail2ban_banned' => 1],
                7200 => ['throttle_exceeded' => 1],
            ],
            $repository->countBlockingEventsPerBucketAndType(0, 3600)
        );
    }

    #[Test]
    public function eventCountsAreGroupedByType(): void
    {
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-a', 1000);
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-b', 1100);
        $this->insertEvent('firewall_error', '', '', 1200);

        $repository = $this->get(EventStatisticsRepository::class);

        self::assertSame(
            ['blocklist_matched' => 2, 'firewall_error' => 1],
            $repository->countEventsByTypeSince(0)
        );
    }

    #[Test]
    public function topRulesAndPathsAreOrderedByCount(): void
    {
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-a', 1000, '/wp-admin');
        $this->insertEvent('blocklist_matched', 'scanner-paths', 'hash-b', 1100, '/wp-admin');
        $this->insertEvent('throttle_exceeded', 'search-throttle', 'hash-c', 1200, '/search');

        $repository = $this->get(EventStatisticsRepository::class);

        self::assertSame(
            [['label' => 'scanner-paths', 'count' => 2], ['label' => 'search-throttle', 'count' => 1]],
            $repository->findTopRulesSince(0)
        );
        self::assertSame(
            [['label' => '/wp-admin', 'count' => 2], ['label' => '/search', 'count' => 1]],
            $repository->findTopPathsSince(0)
        );
    }

    private function insertEvent(string $eventType, string $rule, string $keyHash, int $createdAt, string $requestPath = '/'): void
    {
        $this->getConnectionPool()->getConnectionForTable(EventLogger::TABLE_NAME)->insert(EventLogger::TABLE_NAME, [
            'event_type' => $eventType,
            'rule' => $rule,
            'key_hash' => $keyHash,
            'request_path' => $requestPath,
            'created_at' => $createdAt,
        ]);
    }
}
