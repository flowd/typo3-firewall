<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Pattern\PatternSnapshot;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\Log\LoggerInterface;

/**
 * Pattern backend that persists patterns into a file returning an array.
 * The file returns a list of associative arrays with keys: kind, value, target, expiresAt, addedAt, metadata.
 */
final class FileArrayPatternBackend implements PatternBackendInterface
{
    private const int MAX_ENTRIES = PatternBackendInterface::MAX_ENTRIES_DEFAULT;

    private readonly int $now;

    public function __construct(
        private readonly string $filePath,
        private readonly FileArrayWriter $fileArrayWriter,
        private readonly ?LoggerInterface $logger = null,
        ?int $now = null,
        private readonly PatternEntryValidator $patternEntryValidator = new PatternEntryValidator(),
    ) {
        $this->now = $now ?? time();
    }

    public function consume(): PatternSnapshot
    {
        $this->fileArrayWriter->ensureDirectory();
        $this->fileArrayWriter->ensureFileExists();

        // Use FileArrayWriter's cached mtime - no need to clear stat cache on read
        $mtime = $this->fileArrayWriter->getFileMtime();
        if ($mtime === 0) {
            $mtime = $this->now;
        }

        $raw = $this->fileArrayWriter->readArray();
        $entries = [];
        foreach ($raw as $id => $row) {
            if (!is_string($id)) {
                continue;
            }

            if (!is_array($row)) {
                continue;
            }

            $entry = $this->rowToPatternEntry($id, $row);
            if ($entry instanceof PatternEntry) {
                $entries[] = $entry;
            }
        }

        return new PatternSnapshot($entries, $mtime, $this->filePath);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function rowToPatternEntry(string $id, array $row): ?PatternEntry
    {
        $row = $this->ensureRowScalars($row);
        $kind = is_string($row['kind'] ?? null) ? PatternKind::tryFrom($row['kind']) : null;
        if (!$kind instanceof PatternKind) {
            $this->logger?->warning('Skipping pattern row with unknown kind', [
                'id' => $id,
                'kind' => $row['kind'] ?? null,
            ]);
            return null;
        }

        $metadata = $this->extractMetadata($row);
        $metadata['id'] = $id;

        // Add lastModifiedAt to metadata if it exists
        if (is_int($row['lastModifiedAt'] ?? null)) {
            $metadata['lastModifiedAt'] = $row['lastModifiedAt'];
        }

        return new PatternEntry(
            kind: $kind,
            value: is_string($row['value'] ?? null) ? $row['value'] : '',
            target: is_string($row['target'] ?? null) ? $row['target'] : null,
            expiresAt: is_int($row['expiresAt'] ?? null) ? $row['expiresAt'] : null,
            addedAt: is_int($row['addedAt'] ?? null) ? $row['addedAt'] : null,
            metadata: $metadata,
        );
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, bool|float|int|string>
     */
    private function extractMetadata(array $row): array
    {
        if (isset($row['metadata']) && is_array($row['metadata'])) {
            return array_filter($row['metadata'], is_scalar(...));
        }

        return [];
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    private function ensureRowScalars(array $row): array
    {
        foreach ($row as $key => $val) {
            if ($key !== 'metadata') {
                $row[$key] = $this->ensureScalarValue($val);
            }
        }

        return $row;
    }

    private function ensureScalarValue(mixed $value): bool|float|int|string|null
    {
        if (is_scalar($value) || $value === null) {
            return $value;
        }

        return null;
    }

    public function removeById(string $id): void
    {
        $removedPattern = null;

        $this->fileArrayWriter->readModifyWrite(function (array $data) use ($id, &$removedPattern): ?array {
            if (!isset($data[$id])) {
                return null;
            }

            $removedPattern = $data[$id];
            unset($data[$id]);

            return $data;
        });

        if ($removedPattern !== null) {
            $this->logger?->info('Firewall pattern removed', [
                'id' => $id,
                'kind' => $removedPattern['kind'] ?? 'unknown',
                'value' => $removedPattern['value'] ?? 'unknown',
            ]);
        }
    }

    private function generatePatternHash(PatternEntry $patternEntry): string
    {
        return hash('sha256', $patternEntry->kind->value . '|' . $patternEntry->value . '|' . ($patternEntry->target ?? ''));
    }

    public function append(PatternEntry $patternEntry): void
    {
        $this->patternEntryValidator->validate($patternEntry);

        $now = $this->now;
        $id = $patternEntry->metadata['id'] ?? null;
        if (!is_string($id) || $id === '') {
            $id = $this->generatePatternHash($patternEntry);
        }

        $wasUpdate = false;

        $this->fileArrayWriter->readModifyWrite(function (array $data) use ($patternEntry, $now, $id, &$wasUpdate): array {
            $existingRow = $data[$id] ?? null;

            if ($existingRow === null && count($data) >= self::MAX_ENTRIES) {
                throw new \RuntimeException(
                    sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES),
                    1770244690
                );
            }

            $wasUpdate = $existingRow !== null;
            $data[$id] = $this->createRow($patternEntry, $now, $existingRow);

            return $data;
        });

        $this->logger?->info($wasUpdate ? 'Firewall pattern updated' : 'Firewall pattern added', [
            'id' => $id,
            'kind' => $patternEntry->kind,
            'value' => $patternEntry->value,
        ]);
    }

    /**
     * @param array<string, mixed>|null $existingRow
     * @return array<string, mixed>
     */
    private function createRow(PatternEntry $patternEntry, int $now, ?array $existingRow = null): array
    {
        $addedAt = $patternEntry->addedAt ?? $existingRow['addedAt'] ?? $now;
        $lastModifiedAt = null;
        if ($existingRow !== null) {
            $lastModifiedAt = $now;
        }

        // Extract lastModifiedAt from metadata if provided
        if (isset($patternEntry->metadata['lastModifiedAt']) && is_int($patternEntry->metadata['lastModifiedAt'])) {
            $lastModifiedAt = $patternEntry->metadata['lastModifiedAt'];
        }

        // Remove lastModifiedAt from metadata to avoid duplication since we store it as a direct field
        // BUT keep the id in metadata as it's needed for update detection
        $metadata = $patternEntry->metadata;
        unset($metadata['lastModifiedAt']);

        $row = [
            'kind' => $patternEntry->kind->value,
            'value' => $patternEntry->value,
            'target' => $patternEntry->target,
            'expiresAt' => $patternEntry->expiresAt,
            'addedAt' => $addedAt,
            'metadata' => $metadata,
        ];

        if ($lastModifiedAt !== null) {
            $row['lastModifiedAt'] = $lastModifiedAt;
        }

        return $row;
    }

    public function pruneExpired(): void
    {
        $now = $this->now;
        $prunedCount = 0;

        $this->fileArrayWriter->readModifyWrite(function (array $data) use ($now, &$prunedCount): ?array {
            $originalCount = count($data);

            $data = array_filter($data, static function (array $row) use ($now): bool {
                $expiresAt = $row['expiresAt'] ?? null;
                if (!is_scalar($expiresAt)) {
                    return true;
                }

                return ((int)$expiresAt) > $now;
            });

            $prunedCount = $originalCount - count($data);

            if ($prunedCount === 0) {
                return null;
            }

            return $data;
        });

        if ($prunedCount > 0) {
            $this->logger?->info('Expired firewall patterns pruned', ['count' => $prunedCount]);
        }
    }

    public function type(): string
    {
        return 'php_array';
    }

    /**
     * @return array<string, string|bool>
     */
    public function capabilities(): array
    {
        return [
            'append' => true,
            'pruneExpired' => true,
            'format' => 'php',
            'path' => $this->filePath,
        ];
    }

    public function checkIntegrity(): ?string
    {
        $shapeIssue = $this->fileArrayWriter->checkIntegrity();
        if ($shapeIssue !== null) {
            return $shapeIssue;
        }

        $data = $this->fileArrayWriter->readArray();
        $unknownKinds = 0;
        foreach ($data as $row) {
            $kindValue = is_string($row['kind'] ?? null) ? $row['kind'] : null;
            if ($kindValue === null || !PatternKind::tryFrom($kindValue) instanceof PatternKind) {
                $unknownKinds++;
            }
        }

        if ($unknownKinds > 0) {
            return sprintf(
                '%d of %d pattern entries reference an unknown kind and were skipped.',
                $unknownKinds,
                count($data),
            );
        }

        return null;
    }

    /**
     * Returns patterns with id included in each row for display purposes.
     *
     * @return list<array<string, mixed>>
     */
    public function listRaw(): array
    {
        $data = $this->fileArrayWriter->readArray();
        $result = [];

        foreach ($data as $id => $row) {
            if (is_string($id) && is_array($row)) {
                $row['id'] = $id;
                $result[] = $row;
            }
        }

        return $result;
    }
}
