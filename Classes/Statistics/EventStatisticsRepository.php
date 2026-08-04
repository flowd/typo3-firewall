<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Statistics;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\FirewallEventType;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Aggregates the firewall event log for the statistics view.
 */
final class EventStatisticsRepository
{
    private const int TOP_LIST_LIMIT = 5;

    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    /**
     * Number of distinct blocked clients since the given time.
     */
    public function countDistinctBlockedKeysSince(int $since): int
    {
        $queryBuilder = $this->createQueryBuilder();
        $result = $queryBuilder
            ->addSelectLiteral('COUNT(DISTINCT ' . $queryBuilder->quoteIdentifier('key_hash') . ') AS ' . $queryBuilder->quoteIdentifier('distinct_keys'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('event_type', $this->quotedBlockingTypes($queryBuilder)),
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT)),
                $queryBuilder->expr()->neq('key_hash', $queryBuilder->createNamedParameter(''))
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($result) ? (int)$result : 0;
    }

    /**
     * Blocking event counts grouped into time buckets and event types, oldest first.
     *
     * @return array<int, array<string, int>> bucket start timestamp => event type => count
     */
    public function countBlockingEventsPerBucketAndType(int $since, int $bucketSeconds): array
    {
        $queryBuilder = $this->createQueryBuilder();
        $bucketExpression = sprintf(
            '(%1$s - (%1$s %% %2$d))',
            $queryBuilder->quoteIdentifier('created_at'),
            $bucketSeconds
        );

        $rows = $queryBuilder
            ->addSelectLiteral($bucketExpression . ' AS ' . $queryBuilder->quoteIdentifier('bucket_start'))
            ->addSelect('event_type')
            ->addSelectLiteral('COUNT(*) AS ' . $queryBuilder->quoteIdentifier('event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('event_type', $this->quotedBlockingTypes($queryBuilder)),
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT))
            )
            ->groupBy('bucket_start')
            ->addGroupBy('event_type')
            ->orderBy('bucket_start')
            ->addOrderBy('event_type')
            ->executeQuery()
            ->fetchAllAssociative();

        $buckets = [];
        foreach ($rows as $row) {
            if (is_numeric($row['bucket_start']) && is_string($row['event_type']) && is_numeric($row['event_count'])) {
                $buckets[(int)$row['bucket_start']][$row['event_type']] = (int)$row['event_count'];
            }
        }

        return $buckets;
    }

    /**
     * Event counts per type since the given time.
     *
     * @return array<string, int> event type => count
     */
    public function countEventsByTypeSince(int $since): array
    {
        $queryBuilder = $this->createQueryBuilder();
        $rows = $queryBuilder
            ->select('event_type')
            ->addSelectLiteral('COUNT(*) AS ' . $queryBuilder->quoteIdentifier('event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT))
            )
            ->groupBy('event_type')
            ->orderBy('event_count', 'DESC')
            ->addOrderBy('event_type')
            ->executeQuery()
            ->fetchAllAssociative();

        $counts = [];
        foreach ($rows as $row) {
            if (is_string($row['event_type']) && is_numeric($row['event_count'])) {
                $counts[$row['event_type']] = (int)$row['event_count'];
            }
        }

        return $counts;
    }

    /**
     * The latest blocking events, newest first, with the rule that fired.
     * Each key contributes at most $eventsPerKey of its newest events;
     * events without a key are always included. keyRowNumber numbers each
     * key's events from newest to oldest.
     *
     * The window function requires raw SQL around the inner query builder;
     * the raw part only interpolates quoted identifiers and integer
     * constants, every user-supplied value stays a bound parameter of the
     * inner query.
     *
     * @return list<array{createdAt: int, eventType: string, rule: string, requestMethod: string, requestPath: string, keyDisplay: string, keyHash: string, keyRowNumber: int}>
     */
    public function findRecentBlockingEvents(int $since, int $limit, int $eventsPerKey = 3): array
    {
        $connection = $this->connectionPool->getConnectionForTable(EventLogger::TABLE_NAME);
        $rankedQueryBuilder = $this->createQueryBuilder();
        $rankedQueryBuilder
            ->select('uid', 'created_at', 'event_type', 'rule', 'request_method', 'request_path', 'key_display', 'key_hash')
            ->addSelectLiteral(sprintf(
                'ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s DESC, %s DESC) AS %s',
                $rankedQueryBuilder->quoteIdentifier('key_hash'),
                $rankedQueryBuilder->quoteIdentifier('created_at'),
                $rankedQueryBuilder->quoteIdentifier('uid'),
                $rankedQueryBuilder->quoteIdentifier('key_row_number'),
            ))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $rankedQueryBuilder->expr()->in('event_type', $this->quotedBlockingTypes($rankedQueryBuilder)),
                $rankedQueryBuilder->expr()->gte('created_at', $rankedQueryBuilder->createNamedParameter($since, Connection::PARAM_INT))
            );

        $sql = sprintf(
            "SELECT * FROM (%s) %s WHERE (%s <= %d OR %s = '') ORDER BY %s DESC, %s DESC",
            $rankedQueryBuilder->getSQL(),
            $connection->quoteIdentifier('ranked_events'),
            $connection->quoteIdentifier('key_row_number'),
            $eventsPerKey,
            $connection->quoteIdentifier('key_hash'),
            $connection->quoteIdentifier('created_at'),
            $connection->quoteIdentifier('uid'),
        );
        $sql = $connection->getDatabasePlatform()->modifyLimitQuery($sql, $limit);

        $rows = $connection
            ->executeQuery($sql, $rankedQueryBuilder->getParameters(), $rankedQueryBuilder->getParameterTypes())
            ->fetchAllAssociative();

        $recentEvents = [];
        foreach ($rows as $row) {
            $recentEvent = $this->mapRecentEventRow($row);
            if ($recentEvent !== null) {
                $recentEvents[] = $recentEvent;
            }
        }

        return $recentEvents;
    }

    /**
     * Null for rows with unexpected column types.
     *
     * @param array<string, mixed> $row
     * @return array{createdAt: int, eventType: string, rule: string, requestMethod: string, requestPath: string, keyDisplay: string, keyHash: string, keyRowNumber: int}|null
     */
    private function mapRecentEventRow(array $row): ?array
    {
        if (!is_numeric($row['created_at']) || !is_numeric($row['key_row_number'])) {
            return null;
        }

        if (!is_string($row['event_type']) || !is_string($row['rule']) || !is_string($row['request_method'])) {
            return null;
        }

        if (!is_string($row['request_path']) || !is_string($row['key_display']) || !is_string($row['key_hash'])) {
            return null;
        }

        return [
            'createdAt' => (int)$row['created_at'],
            'eventType' => $row['event_type'],
            'rule' => $row['rule'],
            'requestMethod' => $row['request_method'],
            'requestPath' => $row['request_path'],
            'keyDisplay' => $row['key_display'],
            'keyHash' => $row['key_hash'],
            'keyRowNumber' => (int)$row['key_row_number'],
        ];
    }

    /**
     * Blocking event counts per key hash since the given time, restricted to
     * the given hashes.
     *
     * @param list<string> $keyHashes
     * @return array<string, int>
     */
    public function countBlockingEventsPerKeySince(int $since, array $keyHashes): array
    {
        if ($keyHashes === []) {
            return [];
        }

        $queryBuilder = $this->createQueryBuilder();
        $rows = $queryBuilder
            ->select('key_hash')
            ->addSelectLiteral('COUNT(*) AS ' . $queryBuilder->quoteIdentifier('event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('event_type', $this->quotedBlockingTypes($queryBuilder)),
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT)),
                $queryBuilder->expr()->in('key_hash', array_map(
                    static fn(string $keyHash): string => $queryBuilder->createNamedParameter($keyHash),
                    $keyHashes,
                )),
            )
            ->groupBy('key_hash')
            ->executeQuery()
            ->fetchAllAssociative();

        $counts = [];
        foreach ($rows as $row) {
            if (is_string($row['key_hash']) && is_numeric($row['event_count'])) {
                $counts[$row['key_hash']] = (int)$row['event_count'];
            }
        }

        return $counts;
    }

    /**
     * @return list<array{label: string, count: int}>
     */
    public function findTopRulesSince(int $since): array
    {
        return $this->findTopValuesSince('rule', $since);
    }

    /**
     * @return list<array{label: string, count: int}>
     */
    public function findTopPathsSince(int $since): array
    {
        return $this->findTopValuesSince('request_path', $since);
    }

    /**
     * @return list<array{label: string, count: int}>
     */
    private function findTopValuesSince(string $columnName, int $since): array
    {
        $queryBuilder = $this->createQueryBuilder();
        $rows = $queryBuilder
            ->select($columnName)
            ->addSelectLiteral('COUNT(*) AS ' . $queryBuilder->quoteIdentifier('event_count'))
            ->from(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('event_type', $this->quotedBlockingTypes($queryBuilder)),
                $queryBuilder->expr()->gte('created_at', $queryBuilder->createNamedParameter($since, Connection::PARAM_INT)),
                $queryBuilder->expr()->neq($columnName, $queryBuilder->createNamedParameter(''))
            )
            ->groupBy($columnName)
            ->orderBy('event_count', 'DESC')
            ->addOrderBy($columnName)
            ->setMaxResults(self::TOP_LIST_LIMIT)
            ->executeQuery()
            ->fetchAllAssociative();

        $topValues = [];
        foreach ($rows as $row) {
            if (is_string($row[$columnName]) && is_numeric($row['event_count'])) {
                $topValues[] = ['label' => $row[$columnName], 'count' => (int)$row['event_count']];
            }
        }

        return $topValues;
    }

    /**
     * @return list<string>
     */
    private function quotedBlockingTypes(QueryBuilder $queryBuilder): array
    {
        return array_map(
            static fn(FirewallEventType $firewallEventType): string => $queryBuilder->createNamedParameter($firewallEventType->value),
            FirewallEventType::blockingTypes()
        );
    }

    private function createQueryBuilder(): QueryBuilder
    {
        return $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
    }
}
