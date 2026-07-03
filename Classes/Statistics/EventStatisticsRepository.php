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
