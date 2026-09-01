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
     * @param list<string> $eventTypes
     * @return list<array<string, mixed>>
     */
    public function findLatest(array $eventTypes = [], string $search = '', string $keyHash = '', int $limit = 100, int $offset = 0, string $rule = ''): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('*')
            ->from(EventLogger::TABLE_NAME)
            ->orderBy('created_at', 'DESC')
            ->addOrderBy('uid', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset);
        $this->applyFilters($queryBuilder, $eventTypes, $search, $keyHash, 0, $rule);

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
     * @param list<string> $eventTypes
     * @return list<array<string, mixed>>
     */
    public function findLatestCollapsedByKey(array $eventTypes = [], string $search = '', int $eventsPerKey = 3, int $limit = 100, int $offset = 0, int $since = 0, string $rule = ''): array
    {
        $connection = $this->connectionPool->getConnectionForTable(EventLogger::TABLE_NAME);
        $rankedQueryBuilder = $this->createRankedQueryBuilder($eventTypes, $search, $since, $rule);

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
     * Number of rows the collapsed timeline contains in total; the raw SQL
     * is bound the same way as in findLatestCollapsedByKey().
     *
     * @param list<string> $eventTypes
     */
    public function countCollapsedByKey(array $eventTypes = [], string $search = '', int $eventsPerKey = 3, int $since = 0, string $rule = ''): int
    {
        $connection = $this->connectionPool->getConnectionForTable(EventLogger::TABLE_NAME);
        $rankedQueryBuilder = $this->createRankedQueryBuilder($eventTypes, $search, $since, $rule);

        $sql = sprintf(
            'SELECT COUNT(*) FROM (%s) %s WHERE %s',
            $rankedQueryBuilder->getSQL(),
            $connection->quoteIdentifier('ranked_events'),
            $this->buildCollapseCondition($connection, $eventsPerKey),
        );

        $count = $connection
            ->executeQuery($sql, $rankedQueryBuilder->getParameters(), $rankedQueryBuilder->getParameterTypes())
            ->fetchOne();

        return is_numeric($count) ? (int)$count : 0;
    }

    /**
     * Number of events matching the given filters.
     *
     * @param list<string> $eventTypes
     */
    public function count(array $eventTypes = [], string $search = '', string $keyHash = '', int $since = 0, string $rule = ''): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->count('*')
            ->from(EventLogger::TABLE_NAME);
        $this->applyFilters($queryBuilder, $eventTypes, $search, $keyHash, $since, $rule);

        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) ? (int)$count : 0;
    }

    /**
     * Event counts per key hash, restricted to the given hashes.
     *
     * @param list<string> $eventTypes
     * @param list<string> $keyHashes
     * @return array<string, int>
     */
    public function countByKeyHashes(array $eventTypes, string $search, array $keyHashes, int $since = 0, string $rule = ''): array
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
        $this->applyFilters($queryBuilder, $eventTypes, $search, '', $since, $rule);

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
     *
     * @param list<string> $eventTypes
     */
    private function createRankedQueryBuilder(array $eventTypes, string $search, int $since, string $rule = ''): QueryBuilder
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
        $this->applyFilters($queryBuilder, $eventTypes, $search, '', $since, $rule);

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

    /**
     * @param list<string> $eventTypes
     */
    private function applyFilters(QueryBuilder $queryBuilder, array $eventTypes, string $search, string $keyHash, int $since = 0, string $rule = ''): void
    {
        if ($rule !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('rule', $queryBuilder->createNamedParameter($rule)),
            );
        }

        if ($since > 0) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT)),
            );
        }

        if ($eventTypes !== []) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->in('event_type', array_map(
                    static fn(string $eventType): string => $queryBuilder->createNamedParameter($eventType),
                    $eventTypes,
                )),
            );
        }

        if ($keyHash !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('key_hash', $queryBuilder->createNamedParameter($keyHash)),
            );
        }

        if ($search !== '') {
            $likeValue = '%' . $queryBuilder->escapeLikeWildcards($search) . '%';
            $queryBuilder->andWhere($queryBuilder->expr()->or(
                $queryBuilder->expr()->like('rule', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('key_display', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('request_path', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->eq('key_hash', $queryBuilder->createNamedParameter($this->keyHasher->hash($search))),
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
