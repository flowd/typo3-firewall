<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\EventLog;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogViewDataProvider;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
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

    /** Base lies inside the retention window the collapsed timeline is bounded to. */
    private int $createdAtCounter = 0;

    protected function setUp(): void
    {
        parent::setUp();
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
