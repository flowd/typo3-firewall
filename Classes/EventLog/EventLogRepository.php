<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Reads event log entries for the backend module.
 */
final class EventLogRepository
{
    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    /**
     * Latest events, newest first, with the meta JSON decoded to an array.
     *
     * @return list<array<string, mixed>>
     */
    public function findLatest(string $eventType = '', string $search = '', int $limit = 100): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $queryBuilder
            ->select('*')
            ->from(EventLogger::TABLE_NAME)
            ->orderBy('created_at', 'DESC')
            ->addOrderBy('uid', 'DESC')
            ->setMaxResults($limit);

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

        $rows = $queryBuilder->executeQuery()->fetchAllAssociative();

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
