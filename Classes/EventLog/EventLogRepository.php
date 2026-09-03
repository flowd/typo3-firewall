<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Reads event log entries for the backend module.
 *
 * The search term also matches the keyed hash of the raw key, so a full
 * IP address finds its events even when only an anonymized form (or no
 * readable form at all) is stored in key_display.
 */
final class EventLogRepository
{
    /** Alias name for the ROW_NUMBER() window column of the collapsed timeline. */
    public const string KEY_ROW_NUMBER = 'key_row_number';

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly KeyHasher $keyHasher,
    ) {}

    /**
     * A page of events, newest first, with the meta JSON decoded to an array.
     *
     * @return list<array<string, mixed>>
     */
    public function findLatest(EventLogFilter $eventLogFilter = new EventLogFilter(), int $limit = 100, int $offset = 0): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('*')
            ->from(EventLogger::TABLE_NAME)
            ->orderBy('created_at', 'DESC')
            ->addOrderBy('uid', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset);
        $this->applyFilters($queryBuilder, $eventLogFilter);

        return $this->decodeRows($queryBuilder->executeQuery()->fetchAllAssociative());
    }

    /**
     * A page of the timeline where each key contributes at most $eventsPerKey
     * of its newest events; events without a key are always included. Each row
     * carries a "key_row_number" column (1 = newest event of its key).
     *
     * The window function requires raw SQL around the inner query builder;
     * the raw part only interpolates quoted identifiers and integer
     * constants, every user-supplied value stays a bound parameter of the
     * inner query.
     *
     * @return list<array<string, mixed>>
     */
    public function findLatestCollapsedByKey(EventLogFilter $eventLogFilter = new EventLogFilter(), int $eventsPerKey = 3, int $limit = 100, int $offset = 0): array
    {
        $connection = $this->connectionPool->getConnectionForTable(EventLogger::TABLE_NAME);
        $rankedQueryBuilder = $this->createRankedQueryBuilder($eventLogFilter);

        $sql = sprintf(
            'SELECT * FROM (%s) %s WHERE %s ORDER BY %s DESC, %s DESC',
            $rankedQueryBuilder->getSQL(),
            $connection->quoteIdentifier('ranked_events'),
            $this->buildCollapseCondition($connection, $eventsPerKey),
            $connection->quoteIdentifier('created_at'),
            $connection->quoteIdentifier('uid'),
        );
        $sql = $connection->getDatabasePlatform()->modifyLimitQuery($sql, $limit, $offset);

        $rows = $connection
            ->executeQuery($sql, $rankedQueryBuilder->getParameters(), $rankedQueryBuilder->getParameterTypes())
            ->fetchAllAssociative();

        return $this->decodeRows($rows);
    }

    /**
     * Number of rows the collapsed timeline contains in total.
     *
     * Counts per-key group sizes capped at $eventsPerKey instead of ranking
     * every row with a window function, so no sorted materialization of the
     * whole filtered set is needed. The raw outer SQL only interpolates
     * quoted identifiers, a quoted empty-string literal, and integer
     * constants; every user-supplied value stays a bound parameter of the
     * inner query.
     */
    public function countCollapsedByKey(EventLogFilter $eventLogFilter = new EventLogFilter(), int $eventsPerKey = 3): int
    {
        $connection = $this->connectionPool->getConnectionForTable(EventLogger::TABLE_NAME);

        $groupedQueryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $groupedQueryBuilder
            ->select('key_hash')
            ->addSelectLiteral('COUNT(*) AS ' . $groupedQueryBuilder->quoteIdentifier('key_event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->groupBy('key_hash');
        $this->applyFilters($groupedQueryBuilder, $eventLogFilter);

        $sql = sprintf(
            'SELECT SUM(CASE WHEN %1$s = %2$s THEN %3$s WHEN %3$s > %4$d THEN %4$d ELSE %3$s END) FROM (%5$s) %6$s',
            $connection->quoteIdentifier('key_hash'),
            $connection->quote(''),
            $connection->quoteIdentifier('key_event_count'),
            $eventsPerKey,
            $groupedQueryBuilder->getSQL(),
            $connection->quoteIdentifier('grouped_events'),
        );

        $count = $connection
            ->executeQuery($sql, $groupedQueryBuilder->getParameters(), $groupedQueryBuilder->getParameterTypes())
            ->fetchOne();

        return is_numeric($count) ? (int)$count : 0;
    }

    /**
     * Number of events matching the given filter.
     */
    public function count(EventLogFilter $eventLogFilter = new EventLogFilter()): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->count('*')
            ->from(EventLogger::TABLE_NAME);
        $this->applyFilters($queryBuilder, $eventLogFilter);

        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) ? (int)$count : 0;
    }

    /**
     * Event counts per key hash, restricted to the given hashes. The filter's
     * own key hash is ignored so the counts always cover the listed hashes.
     *
     * @param list<string> $keyHashes
     * @return array<string, int>
     */
    public function countByKeyHashes(EventLogFilter $eventLogFilter, array $keyHashes): array
    {
        if ($keyHashes === []) {
            return [];
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('key_hash')
            ->addSelectLiteral('COUNT(*) AS ' . $queryBuilder->quoteIdentifier('event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('key_hash', array_map(
                    static fn(string $hash): string => $queryBuilder->createNamedParameter($hash),
                    $keyHashes,
                )),
            )
            ->groupBy('key_hash');
        $this->applyFilters($queryBuilder, new EventLogFilter(
            eventTypes: $eventLogFilter->eventTypes,
            search: $eventLogFilter->search,
            rule: $eventLogFilter->rule,
            since: $eventLogFilter->since,
            excludeKeyHashes: $eventLogFilter->excludeKeyHashes,
        ));

        $counts = [];
        foreach ($queryBuilder->executeQuery()->fetchAllAssociative() as $row) {
            if (is_string($row['key_hash']) && is_numeric($row['event_count'])) {
                $counts[$row['key_hash']] = (int)$row['event_count'];
            }
        }

        return $counts;
    }

    /**
     * The distinct event type values present in the table.
     *
     * @return list<string>
     */
    public function findDistinctEventTypes(): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $eventTypes = $queryBuilder
            ->selectLiteral('DISTINCT ' . $queryBuilder->quoteIdentifier('event_type'))
            ->from(EventLogger::TABLE_NAME)
            ->executeQuery()
            ->fetchFirstColumn();

        return array_values(array_filter($eventTypes, is_string(...)));
    }

    /**
     * Whether any event is older than the given timestamp.
     */
    public function hasEventsOlderThan(int $timestamp): bool
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);

        return $queryBuilder
            ->select('uid')
            ->from(EventLogger::TABLE_NAME)
            ->where($queryBuilder->expr()->lt('created_at', $queryBuilder->createNamedParameter($timestamp, Connection::PARAM_INT)))
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne() !== false;
    }

    /**
     * The readable key form of the newest event with the given key hash;
     * empty for hash-only keys and unknown hashes.
     */
    public function findKeyDisplay(string $keyHash): string
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $display = $queryBuilder
            ->select('key_display')
            ->from(EventLogger::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('key_hash', $queryBuilder->createNamedParameter($keyHash)))
            ->orderBy('created_at', 'DESC')
            ->addOrderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return is_string($display) ? $display : '';
    }

    /**
     * Query builder selecting all filtered events plus a ROW_NUMBER() window
     * column numbering each key's events from newest to oldest.
     */
    private function createRankedQueryBuilder(EventLogFilter $eventLogFilter): QueryBuilder
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('*')
            ->addSelectLiteral(sprintf(
                'ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s DESC, %s DESC) AS %s',
                $queryBuilder->quoteIdentifier('key_hash'),
                $queryBuilder->quoteIdentifier('created_at'),
                $queryBuilder->quoteIdentifier('uid'),
                $queryBuilder->quoteIdentifier(self::KEY_ROW_NUMBER),
            ))
            ->from(EventLogger::TABLE_NAME);
        $this->applyFilters($queryBuilder, $eventLogFilter);

        return $queryBuilder;
    }

    private function buildCollapseCondition(Connection $connection, int $eventsPerKey): string
    {
        return sprintf(
            "(%s <= %d OR %s = '')",
            $connection->quoteIdentifier(self::KEY_ROW_NUMBER),
            $eventsPerKey,
            $connection->quoteIdentifier('key_hash'),
        );
    }

    private function applyFilters(QueryBuilder $queryBuilder, EventLogFilter $eventLogFilter): void
    {
        if ($eventLogFilter->rule !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('rule', $queryBuilder->createNamedParameter($eventLogFilter->rule)),
            );
        }

        if ($eventLogFilter->since > 0) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($eventLogFilter->since, Connection::PARAM_INT)),
            );
        }

        if ($eventLogFilter->eventTypes !== []) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->in('event_type', array_map(
                    static fn(string $eventType): string => $queryBuilder->createNamedParameter($eventType),
                    $eventLogFilter->eventTypes,
                )),
            );
        }

        if ($eventLogFilter->keyHash !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('key_hash', $queryBuilder->createNamedParameter($eventLogFilter->keyHash)),
            );
        }

        if ($eventLogFilter->excludeKeyHashes !== []) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->notIn('key_hash', array_map(
                    static fn(string $hash): string => $queryBuilder->createNamedParameter($hash),
                    $eventLogFilter->excludeKeyHashes,
                )),
            );
        }

        if ($eventLogFilter->search !== '') {
            $likeValue = '%' . $queryBuilder->escapeLikeWildcards($eventLogFilter->search) . '%';
            $queryBuilder->andWhere($queryBuilder->expr()->or(
                $queryBuilder->expr()->like('rule', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('key_display', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('request_path', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->eq('key_hash', $queryBuilder->createNamedParameter($this->keyHasher->hash($eventLogFilter->search))),
            ));
        }
    }

    /**
     * @param list<array<string, mixed>> $rows
     * @return list<array<string, mixed>>
     */
    private function decodeRows(array $rows): array
    {
        return array_map(static function (array $row): array {
            $row['meta'] = self::decodeMeta($row['meta'] ?? null);
            return $row;
        }, $rows);
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeMeta(mixed $rawMeta): array
    {
        if (!is_string($rawMeta) || $rawMeta === '') {
            return [];
        }

        try {
            $decoded = json_decode($rawMeta, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }

        return is_array($decoded) ? $decoded : [];
    }
}
