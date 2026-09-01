<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\EventLog;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogRepository;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(EventLogRepository::class)]
final class EventLogRepositoryTest extends FunctionalTestCase
{
    private const string KEY_FLOODER = '203.0.113.10';

    private const string KEY_OTHER = '198.51.100.7';

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    private EventLogRepository $eventLogRepository;

    private int $createdAtCounter = 1_000_000;

    protected function setUp(): void
    {
        parent::setUp();
        $this->eventLogRepository = new EventLogRepository($this->getConnectionPool(), new KeyHasher());
    }

    private function keyHash(string $key): string
    {
        return (new KeyHasher())->hash($key);
    }

    #[Test]
    public function collapsedTimelineLimitsEachKeyToItsNewestEvents(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 5, 'flood-rule-');
        $this->insertKeyedEvents(self::KEY_OTHER, 1, 'other-rule-');
        $this->insertKeylessEvents(4, 'probe-rule-');

        $rows = $this->eventLogRepository->findLatestCollapsedByKey();

        self::assertCount(8, $rows);
        self::assertSame(8, $this->eventLogRepository->countCollapsedByKey());
        $flooderRules = $this->rulesOfKey($rows, self::KEY_FLOODER);
        self::assertSame(['flood-rule-4', 'flood-rule-3', 'flood-rule-2'], $flooderRules);
        self::assertCount(4, $this->rulesOfKey($rows, ''));
    }

    #[Test]
    public function collapsedTimelineMarksTheCappedRowWithItsKeyRowNumber(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 5, 'flood-rule-');

        $rows = $this->eventLogRepository->findLatestCollapsedByKey();

        self::assertSame([1, 2, 3], array_map(
            static fn(array $row): int => is_numeric($row[EventLogRepository::KEY_ROW_NUMBER]) ? (int)$row[EventLogRepository::KEY_ROW_NUMBER] : -1,
            $rows,
        ));
    }

    #[Test]
    public function collapsedTimelineHonorsTheSinceBound(): void
    {
        $this->insertKeylessEvents(4, 'probe-rule-');

        $rows = $this->eventLogRepository->findLatestCollapsedByKey(since: 1_000_003);

        self::assertSame(['probe-rule-3', 'probe-rule-2'], array_column($rows, 'rule'));
        self::assertSame(2, $this->eventLogRepository->countCollapsedByKey(since: 1_000_003));
    }

    #[Test]
    public function collapsedTimelinePaginatesWithLimitAndOffset(): void
    {
        $this->insertKeylessEvents(6, 'probe-rule-');

        $rows = $this->eventLogRepository->findLatestCollapsedByKey(limit: 3, offset: 3);

        self::assertSame(['probe-rule-2', 'probe-rule-1', 'probe-rule-0'], array_column($rows, 'rule'));
    }

    #[Test]
    public function collapsedTimelineRespectsTheEventTypeFilter(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 2, 'flood-rule-', 'throttle_exceeded');
        $this->insertKeylessEvents(2, 'probe-rule-', 'blocklist_matched');

        $rows = $this->eventLogRepository->findLatestCollapsedByKey(['throttle_exceeded']);

        self::assertSame(['flood-rule-1', 'flood-rule-0'], array_column($rows, 'rule'));
    }

    #[Test]
    public function findLatestFiltersByKeyHash(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 5, 'flood-rule-');
        $this->insertKeyedEvents(self::KEY_OTHER, 2, 'other-rule-');

        $rows = $this->eventLogRepository->findLatest(keyHash: $this->keyHash(self::KEY_FLOODER));

        self::assertCount(5, $rows);
        self::assertSame(5, $this->eventLogRepository->count(keyHash: $this->keyHash(self::KEY_FLOODER)));
    }

    #[Test]
    public function findLatestFiltersByMultipleEventTypes(): void
    {
        $this->insertKeylessEvents(1, 'probe-rule-', 'blocklist_matched');
        $this->insertKeylessEvents(1, 'tracked-rule-', 'track_hit');
        $this->insertKeylessEvents(1, 'error-rule-', 'firewall_error');

        $rows = $this->eventLogRepository->findLatest(['track_hit', 'firewall_error']);

        self::assertSame(['error-rule-0', 'tracked-rule-0'], array_column($rows, 'rule'));
    }

    #[Test]
    public function findLatestFiltersByRule(): void
    {
        $this->insertKeylessEvents(2, 'probe-rule-');

        $rows = $this->eventLogRepository->findLatest(rule: 'probe-rule-0');

        self::assertSame(['probe-rule-0'], array_column($rows, 'rule'));
    }

    #[Test]
    public function searchMatchesTheHashOfTheFullKeyDespiteAnonymizedDisplay(): void
    {
        $this->insertEvent([
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('20.251.48.208'),
            'key_display' => '20.251.48.0',
        ]);
        $this->insertKeyedEvents(self::KEY_OTHER, 1, 'other-rule-');

        $rows = $this->eventLogRepository->findLatest(search: '20.251.48.208');

        self::assertSame(['flood-rule'], array_column($rows, 'rule'));
        self::assertSame(1, $this->eventLogRepository->count(search: '20.251.48.208'));
    }

    #[Test]
    public function searchStillMatchesRuleKeyDisplayAndPath(): void
    {
        $this->insertEvent(['rule' => 'login-brute-force', 'request_path' => '/login']);
        $this->insertEvent(['rule' => 'env-probe', 'request_path' => '/.env']);

        self::assertSame(['login-brute-force'], array_column($this->eventLogRepository->findLatest(search: 'login'), 'rule'));
        self::assertSame(['env-probe'], array_column($this->eventLogRepository->findLatest(search: '.env'), 'rule'));
    }

    #[Test]
    public function countByKeyHashesCountsOnlyTheRequestedKeysWithFilters(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 4, 'flood-rule-', 'throttle_exceeded');
        $this->insertKeyedEvents(self::KEY_FLOODER, 2, 'ban-rule-', 'fail2ban_banned');
        $this->insertKeyedEvents(self::KEY_OTHER, 3, 'other-rule-', 'throttle_exceeded');

        $flooderHash = $this->keyHash(self::KEY_FLOODER);
        $counts = $this->eventLogRepository->countByKeyHashes(['throttle_exceeded'], '', [$flooderHash]);

        self::assertSame([$flooderHash => 4], $counts);
        self::assertSame([], $this->eventLogRepository->countByKeyHashes([], '', []));
    }

    #[Test]
    public function findKeyDisplayReturnsTheNewestDisplayValue(): void
    {
        $keyHash = $this->keyHash(self::KEY_FLOODER);
        $this->insertEvent(['key_hash' => $keyHash, 'key_display' => '203.0.113.10']);
        $this->insertEvent(['key_hash' => $keyHash, 'key_display' => '203.0.113.0']);

        self::assertSame('203.0.113.0', $this->eventLogRepository->findKeyDisplay($keyHash));
        self::assertSame('', $this->eventLogRepository->findKeyDisplay($this->keyHash('unknown')));
    }

    #[Test]
    public function findDistinctEventTypesReturnsEachTypePresentInTheTableOnce(): void
    {
        $this->insertKeylessEvents(2, 'scanner-', 'blocklist_matched');
        $this->insertKeylessEvents(1, 'tracked-', 'track_hit');
        $this->insertKeylessEvents(1, 'error-', 'firewall_error');

        $eventTypes = $this->eventLogRepository->findDistinctEventTypes();
        sort($eventTypes);

        self::assertSame(['blocklist_matched', 'firewall_error', 'track_hit'], $eventTypes);
    }

    #[Test]
    public function findDistinctEventTypesReturnsNothingForAnEmptyTable(): void
    {
        self::assertSame([], $this->eventLogRepository->findDistinctEventTypes());
    }

    private function insertKeyedEvents(string $key, int $count, string $rulePrefix, string $eventType = 'throttle_exceeded'): void
    {
        for ($i = 0; $i < $count; ++$i) {
            $this->insertEvent([
                'event_type' => $eventType,
                'rule' => $rulePrefix . $i,
                'key_hash' => $this->keyHash($key),
                'key_display' => $key,
            ]);
        }
    }

    private function insertKeylessEvents(int $count, string $rulePrefix, string $eventType = 'blocklist_matched'): void
    {
        for ($i = 0; $i < $count; ++$i) {
            $this->insertEvent([
                'event_type' => $eventType,
                'rule' => $rulePrefix . $i,
            ]);
        }
    }

    /**
     * Inserts an event; created_at increases with every call, so later
     * inserts are newer.
     *
     * @param array<string, int|string> $eventRow
     */
    private function insertEvent(array $eventRow): void
    {
        $this->getConnectionPool()->getConnectionForTable(EventLogger::TABLE_NAME)->insert(EventLogger::TABLE_NAME, array_merge([
            'event_type' => 'throttle_exceeded',
            'created_at' => ++$this->createdAtCounter,
        ], $eventRow));
    }

    /**
     * @param list<array<string, mixed>> $rows
     * @return list<string>
     */
    private function rulesOfKey(array $rows, string $key): array
    {
        $keyHash = $key === '' ? '' : $this->keyHash($key);

        $rules = [];
        foreach ($rows as $row) {
            if ($row['key_hash'] === $keyHash && is_string($row['rule'])) {
                $rules[] = $row['rule'];
            }
        }

        return $rules;
    }
}
