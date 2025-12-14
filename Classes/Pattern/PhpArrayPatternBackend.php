<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternSnapshot;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;

/**
 * Pattern backend that persists patterns into a PHP file returning an array.
 * The file returns a list of associative arrays with keys: kind, value, target, expiresAt, addedAt, metadata.
 */
final class PhpArrayPatternBackend implements PatternBackendInterface
{
    /** @var int */
    private const MAX_ENTRIES = PatternBackendInterface::MAX_ENTRIES_DEFAULT;

    private readonly int $now;
    private FileArrayWriter $fileHelper;

    public function __construct(private readonly string $filePath, int $now = null)
    {
        $this->now = $now ?? time();
        $this->fileHelper = new FileArrayWriter($filePath);
    }

    public function consume(): PatternSnapshot
    {
        $this->fileHelper->ensureDirectory();
        $this->fileHelper->ensureFileExists();
        clearstatcache(false, $this->filePath);
        $mtime = @filemtime($this->filePath);
        if ($mtime === false) {
            $mtime = $this->now;
        }
        $raw = $this->fileHelper->readArray();
        $entries = array_map(fn(array $row): PatternEntry => $this->rowToPatternEntry($row), $raw);
        return new PatternSnapshot($entries, $mtime, $this->filePath);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function rowToPatternEntry(array $row): PatternEntry
    {
        $row = $this->ensureRowScalars($row);
        $metadata = $this->extractMetadata($row);
        return new PatternEntry(
            kind: is_string($row['kind'] ?? null) ? $row['kind'] : '',
            value: is_string($row['value'] ?? null) ? $row['value'] : '',
            target: isset($row['target']) && is_string($row['target']) ? $row['target'] : null,
            expiresAt: isset($row['expiresAt']) && is_int($row['expiresAt']) ? $row['expiresAt'] : null,
            addedAt: isset($row['addedAt']) && is_int($row['addedAt']) ? $row['addedAt'] : null,
            metadata: $metadata,
        );
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, bool|float|int|string>
     */
    private function extractMetadata(array $row): array
    {
        $metadata = [];
        if (isset($row['metadata']) && is_array($row['metadata'])) {
            $metadata = array_filter($row['metadata'], static fn(mixed $v): bool => is_scalar($v));
        }
        if (isset($row['id']) && is_string($row['id'])) {
            $metadata['id'] = $row['id'];
        }
        return $metadata;
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

    /**
     * @return bool|float|int|string|null
     */
    private function ensureScalarValue(mixed $value): bool|float|int|string|null
    {
        if (is_scalar($value) || $value === null) {
            return $value;
        }
        return null;
    }

    public function removeById(string $id): void
    {
        $data = $this->fileHelper->readArray();
        $found = false;
        foreach ($data as $idx => $row) {
            if (($row['id'] ?? null) === $id) {
                array_splice($data, $idx, 1);
                $found = true;
                break;
            }
        }
        if ($found) {
            $this->fileHelper->writeArray(array_values($data));
        }
    }

    private function generatePatternHash(PatternEntry $patternEntry): string
    {
        return hash('sha256', $patternEntry->kind . '|' . $patternEntry->value . '|' . ($patternEntry->target ?? ''));
    }

    public function append(PatternEntry $patternEntry): void
    {
        $this->fileHelper->ensureDirectory();
        $this->fileHelper->ensureFileExists();
        $now = $this->now;
        $data = $this->fileHelper->readArray();
        $id = $patternEntry->metadata['id'] ?? null;
        if (!is_string($id) || $id === '') {
            $id = $this->generatePatternHash($patternEntry);
        }
        $row = $this->createRow($patternEntry, $id, $now);
        if (count($data) >= self::MAX_ENTRIES) {
            throw new \RuntimeException(sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES), 6857001936);
        }
        if ($this->updateIfDuplicate($data, $row)) {
            $this->fileHelper->writeArray(array_values($data));
            return;
        }
        $data[] = $row;
        $this->fileHelper->writeArray(array_values($data));
    }

    /**
     * @param PatternEntry $patternEntry
     * @param string $id
     * @param int $now
     * @return array<string, mixed>
     */
    private function createRow(PatternEntry $patternEntry, string $id, int $now): array
    {
        $row = [
            'id' => $id,
            'kind' => $patternEntry->kind,
            'value' => $patternEntry->value,
            'target' => $patternEntry->target,
            'expiresAt' => $patternEntry->expiresAt,
            'addedAt' => $patternEntry->addedAt ?? $now,
            'metadata' => $patternEntry->metadata,
        ];
        $row['metadata']['id'] = $id;
        return $row;
    }

    /**
     * @param array<int, array<string, mixed>> $data
     * @param array<string, mixed> $row
     * @return bool true if updated
     */
    private function updateIfDuplicate(array &$data, array $row): bool
    {
        foreach ($data as &$existing) {
            if (($existing['kind'] ?? null) === $row['kind']
                && ($existing['value'] ?? null) === $row['value']
                && (($existing['target'] ?? null) === $row['target'])) {
                $existing = array_merge($existing, array_filter($row, static fn(mixed $v): bool => $v !== null));
                return true;
            }
        }
        unset($existing);
        return false;
    }

    public function pruneExpired(): void
    {
        $data = $this->fileHelper->readArray();
        $now = $this->now;
        $data = array_values(array_filter($data, static function (array $row) use ($now): bool {
            $expiresAt = $row['expiresAt'] ?? null;
            if (!is_scalar($expiresAt)) {
                return true;
            }
            return ((int)$expiresAt) > $now;
        }));
        $this->fileHelper->writeArray($data);
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

    /**
     * @return list<array<string, mixed>>
     */
    public function listRaw(): array
    {
        return $this->fileHelper->readArray();
    }
}
