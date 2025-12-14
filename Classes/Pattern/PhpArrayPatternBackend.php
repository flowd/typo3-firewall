<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Flowd\Phirewall\Pattern\PatternBackendInterface;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternSnapshot;

/**
 * Pattern backend that persists patterns into a PHP file returning an array.
 * The file returns a list of associative arrays with keys: kind, value, target, expiresAt, addedAt, metadata.
 */
final class PhpArrayPatternBackend implements PatternBackendInterface
{
    private const MAX_ENTRIES = self::MAX_ENTRIES_DEFAULT;

    private int $now;

    public function __construct(private readonly string $filePath, int $now = null)
    {
        $this->now = $now ?? time();
    }

    public function consume(): PatternSnapshot
    {
        $this->ensureDirectory();
        $this->ensureFileExists();

        clearstatcache(false, $this->filePath);
        $mtime = @filemtime($this->filePath);
        if ($mtime === false) {
            $mtime = $this->now;
        }

        $raw = $this->readArray();
        $entries = [];
        foreach ($raw as $row) {
            $patternEntry = $this->rowToPatternEntry($row);
            if ($patternEntry instanceof PatternEntry) {
                $entries[] = $patternEntry;
            }
        }

        return new PatternSnapshot($entries, $mtime, $this->filePath);
    }

    /**
     * @param array<mixed> $row
     */
    private function rowToPatternEntry(array $row): ?PatternEntry
    {
        foreach ($row as $key => $val) {
            if ($key !== 'metadata') {
                $row[$key] = $this->ensureScalarValue($val);
            }
        }

        $metadata = is_array($row['metadata'] ?? null) ? $row['metadata'] : [];
        if (isset($row['id'])) {
            $metadata['id'] = $row['id'];
        }

        return new PatternEntry(
            kind: (string)$row['kind'],
            value: (string)$row['value'],
            target: isset($row['target']) ? (string)$row['target'] : null,
            expiresAt: isset($row['expiresAt']) ? (int)$row['expiresAt'] : null,
            addedAt: isset($row['addedAt']) ? (int)$row['addedAt'] : null,
            metadata: $metadata,
        );
    }

    /**
     * @param mixed $value
     * @return ?scalar
     */
    private function ensureScalarValue(mixed $value): mixed
    {
        if (!is_scalar($value) && $value !== null) {
            return null;
        }
        return $value;
    }

    /**
     * Remove entry by its unique hash id in the array file.
     */
    public function removeById(string $id): void
    {
        $data = $this->readArray();
        $found = false;
        foreach ($data as $idx => $row) {
            if (($row['id'] ?? null) === $id) {
                array_splice($data, $idx, 1);
                $found = true;
                break;
            }
        }

        if ($found) {
            $this->writeArray($data);
        }
    }

    /**
     * Generate a stable hash for a pattern entry (kind, value, target).
     */
    private function generatePatternHash(PatternEntry $patternEntry): string
    {
        return sha1($patternEntry->kind . '|' . $patternEntry->value . '|' . ($patternEntry->target ?? ''));
    }

    public function append(PatternEntry $patternEntry): void
    {
        $this->ensureDirectory();
        $this->ensureFileExists();

        $now = $this->now;
        $data = $this->readArray();

        // Generate or keep id (hash)
        $id = $patternEntry->metadata['id'] ?? null;
        if (!is_string($id) || $id === '') {
            $id = $this->generatePatternHash($patternEntry);
        }

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

        // Prevent uncontrolled growth
        if (count($data) >= self::MAX_ENTRIES) {
            throw new \RuntimeException(sprintf('Pattern file exceeds maximum entries (%d).', self::MAX_ENTRIES));
        }

        // De-duplicate simple duplicates (same kind/value/target)
        $exists = false;
        foreach ($data as &$existing) {
            if (($existing['kind'] ?? null) === $row['kind']
                && ($existing['value'] ?? null) === $row['value']
                && (($existing['target'] ?? null) === $row['target'])) {
                $existing = array_merge($existing, array_filter($row, static fn($v): bool => $v !== null));
                $exists = true;
                break;
            }
        }

        unset($existing);

        if (!$exists) {
            $data[] = $row;
        }

        $this->writeArray($data);
    }

    public function pruneExpired(): void
    {
        $data = $this->readArray();
        $now = $this->now;
        $data = array_values(array_filter($data, static function (array $row) use ($now): bool {
            $expiresAt = $row['expiresAt'] ?? null;
            if (!is_scalar($expiresAt)) {
                return true;
            }

            return ((int)$expiresAt) > $now;
        }));
        $this->writeArray($data);
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
     * Return raw array representation for UI usage.
     *
     * @return list<array<string, mixed>>
     */
    public function listRaw(): array
    {
        return $this->readArray();
    }

    /**
     * Remove entry by its numeric index in the array file.
     */
    public function removeAt(int $index): void
    {
        $data = $this->readArray();
        if (!isset($data[$index])) {
            return;
        }

        array_splice($data, $index, 1);
        $this->writeArray($data);
    }

    private function ensureDirectory(): void
    {
        $dir = \dirname($this->filePath);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Cannot create directory: %s', $dir));
        }
    }

    private function ensureFileExists(): void
    {
        if (!@is_file($this->filePath)) {
            $this->writeArray([]);
        }
    }

    /**
     * @return list<array<mixed>>
     */
    private function readArray(): array
    {
        if (!@is_file($this->filePath)) {
            return [];
        }

        $data = @include $this->filePath;
        if (!\is_array($data)) {
            return [];
        }

        // ensure list semantics
        $data = array_filter($data, static fn($item): bool => is_array($item));

        return array_values($data);
    }

    /**
     * @param list<array<string, mixed>> $data
     */
    private function writeArray(array $data): void
    {
        $this->ensureDirectory();
        $tmp = $this->filePath . '.tmp';
        $php = "<?php\nreturn " . var_export($data, true) . ";\n";
        if (@file_put_contents($tmp, $php) === false) {
            throw new \RuntimeException(sprintf('Cannot write temp pattern file: %s', $tmp));
        }

        // fallback: write directly
        if (!@rename($tmp, $this->filePath) && @file_put_contents($this->filePath, $php) === false) {
            throw new \RuntimeException(sprintf('Cannot write pattern file: %s', $this->filePath));
        }

        @chmod($this->filePath, 0664);
    }
}
