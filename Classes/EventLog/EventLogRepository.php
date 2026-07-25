<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Reads event log entries for the backend module.
 */
final class EventLogRepository
{
    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    /**
     * A page of events, newest first, with the meta JSON decoded to an array.
     *
     * @return list<array<string, mixed>>
     */
    public function findLatest(string $eventType = '', string $search = '', int $limit = 100, int $offset = 0): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('*')
            ->from(EventLogger::TABLE_NAME)
            ->orderBy('created_at', 'DESC')
            ->addOrderBy('uid', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset);
        $this->applyFilters($queryBuilder, $eventType, $search);

        $rows = $queryBuilder->executeQuery()->fetchAllAssociative();

        return array_map(static function (array $row): array {
            $row['meta'] = self::decodeMeta($row['meta'] ?? null);
            return $row;
        }, $rows);
    }

    /**
     * Number of events matching the given filters.
     */
    public function count(string $eventType = '', string $search = ''): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->count('*')
            ->from(EventLogger::TABLE_NAME);
        $this->applyFilters($queryBuilder, $eventType, $search);

        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) ? (int)$count : 0;
    }

    private function applyFilters(QueryBuilder $queryBuilder, string $eventType, string $search): void
    {
        if ($eventType !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('event_type', $queryBuilder->createNamedParameter($eventType)),
            );
        }

        if ($search !== '') {
            $likeValue = '%' . $queryBuilder->escapeLikeWildcards($search) . '%';
            $queryBuilder->andWhere($queryBuilder->expr()->or(
                $queryBuilder->expr()->like('rule', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('key_display', $queryBuilder->createNamedParameter($likeValue)),
                $queryBuilder->expr()->like('request_path', $queryBuilder->createNamedParameter($likeValue)),
            ));
        }
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
