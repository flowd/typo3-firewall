<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogViewDataProvider;
use Flowd\Typo3Firewall\EventLog\KeyBlockStatus;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Pattern\PatternStorageSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(EventLogViewDataProvider::class)]
final class EventLogViewDataProviderTest extends FunctionalTestCase
{
    private const string KEY_FLOODER = '203.0.113.10';

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    private EventLogViewDataProvider $eventLogViewDataProvider;

    /** Increases per insert so later inserts are newer. */
    private int $createdAtCounter = 0;

    protected function setUp(): void
    {
        parent::setUp();

        // The instance directory survives between tests, only the database is
        // reset; a pattern file from a previous test must not leak in.
        $patternsFilePath = $this->get(PatternStorageSettings::class)->getPatternsFilePath();
        if (is_file($patternsFilePath)) {
            unlink($patternsFilePath);
        }

        $this->eventLogViewDataProvider = $this->get(EventLogViewDataProvider::class);
        $this->createdAtCounter = time() - 100_000;
    }

    private function keyHash(string $key): string
    {
        return (new KeyHasher())->hash($key);
    }

    #[Test]
    public function getViewDataAttachesTheHiddenEventCountToTheCappedRow(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 5, 'flood-rule-');

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        self::assertNull($viewData['keyFilter']);
        self::assertSame(['flood-rule-4', 'flood-rule-3', 'flood-rule-2'], array_column($events, 'rule'));
        self::assertSame([0, 0, 2], array_column($events, 'moreEventsCount'));
    }

    #[Test]
    public function getViewDataDoesNotFlagMoreEventsForAKeyWithExactlyThreeEvents(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 3, 'flood-rule-');

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        self::assertSame(['flood-rule-2', 'flood-rule-1', 'flood-rule-0'], array_column($events, 'rule'));
        self::assertSame([0, 0, 0], array_column($events, 'moreEventsCount'));
    }

    #[Test]
    public function getViewDataDropsUnknownEventTypesFromTheFilter(): void
    {
        $this->insertEvent(['event_type' => 'throttle_exceeded', 'rule' => 'kept-rule']);
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'dropped-rule']);

        $viewData = $this->eventLogViewDataProvider->getViewData(['throttle_exceeded', 42, 'not-a-type', 'throttle_exceeded'], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        self::assertSame(['throttle_exceeded'], $viewData['currentTypes']);
        self::assertSame(['kept-rule'], array_column($events, 'rule'));
    }

    #[Test]
    public function getViewDataIgnoresAMalformedKeyHashAndShowsTheCollapsedTimeline(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 5, 'flood-rule-');

        foreach (['not-a-hash', strtoupper($this->keyHash(self::KEY_FLOODER))] as $malformedKey) {
            $viewData = $this->eventLogViewDataProvider->getViewData([], '', $malformedKey);
            $events = $viewData['events'];
            self::assertIsArray($events);

            self::assertNull($viewData['keyFilter']);
            self::assertCount(3, $events);
        }
    }

    #[Test]
    public function typeFiltersOfferOnlyEventTypesPresentInTheTable(): void
    {
        $this->insertEvent(['event_type' => 'track_hit', 'rule' => 'observed-endpoint']);
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'scanner-paths']);
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'scanner-paths']);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $typeFilters = $viewData['typeFilters'];
        self::assertIsArray($typeFilters);

        self::assertSame(
            ['blocklist_matched', 'track_hit'],
            array_column($typeFilters, 'value'),
            'Only types with rows are offered, in the enum declaration order',
        );
    }

    #[Test]
    public function typeFiltersKeepAnActiveFilterWhoseTypeHasNoRows(): void
    {
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'scanner-paths']);

        $viewData = $this->eventLogViewDataProvider->getViewData(['track_hit'], '', '');
        $typeFilters = $viewData['typeFilters'];
        self::assertIsArray($typeFilters);

        self::assertSame(['blocklist_matched', 'track_hit'], array_column($typeFilters, 'value'));
        $staleFilter = $typeFilters[1];
        self::assertIsArray($staleFilter);
        self::assertTrue($staleFilter['active'], 'The persisted filter stays visible so it can be toggled off');
        self::assertSame([], $staleFilter['toggledTypes'], 'A click removes the stale filter');
    }

    #[Test]
    public function eventsOlderThanTheRetentionStayVisibleAndFlagTheOverduePrune(): void
    {
        // The retention period only drives the prune command; rows it has not
        // removed yet stay visible and searchable in the "all" range, and
        // their age surfaces as the prune-overdue notice instead.
        $this->insertEvent(['event_type' => 'fail2ban_matched', 'rule' => 'stale-rule', 'created_at' => time() - 40 * 86400]);
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'fresh-rule', 'created_at' => time() - 3600]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '', range: 'all');
        $events = $viewData['events'];
        self::assertIsArray($events);
        $typeFilters = $viewData['typeFilters'];
        self::assertIsArray($typeFilters);

        self::assertSame(['fresh-rule', 'stale-rule'], array_column($events, 'rule'));
        self::assertSame(['blocklist_matched', 'fail2ban_matched'], array_column($typeFilters, 'value'));
        self::assertTrue($viewData['pruneOverdue']);
    }

    #[Test]
    public function theDefaultRangeHidesEventsOlderThanSevenDays(): void
    {
        $this->insertEvent(['event_type' => 'fail2ban_matched', 'rule' => 'stale-rule', 'created_at' => time() - 8 * 86400]);
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'fresh-rule', 'created_at' => time() - 3600]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        self::assertSame('7d', $viewData['range']);
        self::assertSame(['24h', '7d', '30d', 'all'], $viewData['ranges']);
        self::assertSame(['fresh-rule'], array_column($events, 'rule'));
    }

    #[Test]
    public function anUnknownRangeFallsBackToTheDefault(): void
    {
        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '', range: 'yesterday');

        self::assertSame('7d', $viewData['range']);
    }

    #[Test]
    public function excludedKeysAreHiddenAndListedAsChips(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 2, 'flood-rule-');
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'other-rule']);

        $flooderHash = $this->keyHash(self::KEY_FLOODER);
        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '', excludeKeys: [$flooderHash, 'not-a-hash']);
        $events = $viewData['events'];
        self::assertIsArray($events);

        self::assertSame(['other-rule'], array_column($events, 'rule'));
        self::assertSame([$flooderHash], $viewData['excludeKeyHashes']);
        self::assertSame(
            [['hash' => $flooderHash, 'display' => self::KEY_FLOODER, 'remainingHashes' => []]],
            $viewData['excludedKeyChips'],
        );
    }

    #[Test]
    public function aKeyWithAFullIpDisplayOffersTheIpBlockAction(): void
    {
        $this->insertKeyedEvents(self::KEY_FLOODER, 1, 'flood-rule-');

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $event = $events[0];
        self::assertIsArray($event);
        self::assertNull($event['blockStatus']);
        self::assertSame('ip', $event['blockAction']);
        self::assertSame(self::KEY_FLOODER, $event['blockValue']);
    }

    #[Test]
    public function anAnonymizedKeyDisplayOffersNoBlockAction(): void
    {
        $this->insertEvent([
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash(self::KEY_FLOODER),
            'key_display' => '203.0.113.0',
        ]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $event = $events[0];
        self::assertIsArray($event);
        self::assertNull($event['blockAction'], 'The real client IP behind an anonymized address is unknown, so no block is offered');
    }

    #[Test]
    public function aHashOnlyKeyOffersNoBlockAction(): void
    {
        $this->insertEvent([
            'event_type' => 'throttle_exceeded',
            'rule' => 'header-rule',
            'key_hash' => $this->keyHash('api-token-value'),
            'key_display' => '',
        ]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $event = $events[0];
        self::assertIsArray($event);
        self::assertNull($event['blockStatus']);
        self::assertNull($event['blockAction']);
    }

    #[Test]
    public function aKeyMatchingAnIpPatternEntryCarriesTheBlockedStatusAndNoBlockAction(): void
    {
        $this->createPatternBackend()->append(new PatternEntry(kind: PatternKind::IP, value: self::KEY_FLOODER));
        $this->insertKeyedEvents(self::KEY_FLOODER, 1, 'flood-rule-');

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $event = $events[0];
        self::assertIsArray($event);
        $blockStatus = $event['blockStatus'];
        self::assertInstanceOf(KeyBlockStatus::class, $blockStatus);
        self::assertSame(KeyBlockStatus::SOURCE_PATTERN, $blockStatus->source);
        self::assertSame('ip ' . self::KEY_FLOODER, $blockStatus->detail);
        self::assertNull($event['blockAction']);
    }

    #[Test]
    public function recordedRequestHeadersAreSplitIntoTheirOwnLines(): void
    {
        $this->insertEvent([
            'event_type' => 'blocklist_matched',
            'rule' => 'scanner-paths',
            'meta' => '{"owasp_rule_id":930121,"requestHeaders":{"Host":"example.com","User-Agent":"sqlmap/1.0"}}',
        ]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $event = $events[0];
        self::assertIsArray($event);
        self::assertSame(['Host: example.com', 'User-Agent: sqlmap/1.0'], $event['requestHeaderLines']);
        self::assertSame(['owasp_rule_id: 930121'], $event['metaLines'], 'The headers do not appear as meta lines');
    }

    #[Test]
    public function aMatchedRuleListOnlyRepeatingThePrimaryRuleIdIsShownOnce(): void
    {
        $this->insertEvent([
            'event_type' => 'blocklist_matched',
            'rule' => 'owasp-single',
            'meta' => '{"owasp_rule_ids":"930121","owasp_rule_id":930121}',
        ]);
        $this->insertEvent([
            'event_type' => 'blocklist_matched',
            'rule' => 'owasp-multi',
            'meta' => '{"owasp_rule_ids":"930121,942100","owasp_rule_id":930121}',
        ]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');
        $events = $viewData['events'];
        self::assertIsArray($events);

        $multiRuleEvent = $events[0];
        self::assertIsArray($multiRuleEvent);
        self::assertSame(['owasp_rule_ids: 930121,942100', 'owasp_rule_id: 930121'], $multiRuleEvent['metaLines']);

        $singleRuleEvent = $events[1];
        self::assertIsArray($singleRuleEvent);
        self::assertSame(['owasp_rule_id: 930121'], $singleRuleEvent['metaLines']);
    }

    private function createPatternBackend(): FileArrayPatternBackend
    {
        return FileArrayPatternBackend::forFile($this->get(PatternStorageSettings::class)->getPatternsFilePath());
    }

    #[Test]
    public function pruneIsNotOverdueWhenAllEventsAreWithinTheRetention(): void
    {
        $this->insertEvent(['event_type' => 'blocklist_matched', 'rule' => 'fresh-rule', 'created_at' => time() - 3600]);

        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');

        self::assertFalse($viewData['pruneOverdue']);
    }

    #[Test]
    public function typeFiltersAreEmptyForAnEmptyLog(): void
    {
        $viewData = $this->eventLogViewDataProvider->getViewData([], '', '');

        self::assertSame([], $viewData['typeFilters']);
    }

    private function insertKeyedEvents(string $key, int $count, string $rulePrefix): void
    {
        for ($i = 0; $i < $count; ++$i) {
            $this->insertEvent([
                'event_type' => 'throttle_exceeded',
                'rule' => $rulePrefix . $i,
                'key_hash' => $this->keyHash($key),
                'key_display' => $key,
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
}
