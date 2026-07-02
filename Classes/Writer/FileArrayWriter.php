<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Writer;

use Psr\Log\LoggerInterface;

/**
 * Handles safe file I/O for pattern array persistence using JSON format.
 *
 * Security notes:
 * - Uses JSON instead of PHP serialization to prevent code execution
 * - Validates all data is scalar before writing
 *
 * @internal
 */
final class FileArrayWriter
{
    public function __construct(
        private readonly string $filePath,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function ensureFileExists(): void
    {
        if (!is_file($this->filePath)) {
            $this->writeArray([]);
        }
    }

    /**
     * Reads the array from JSON file.
     *
     * @return array<string, array<string, mixed>>
     */
    public function readArray(): array
    {
        if (!is_file($this->filePath)) {
            return [];
        }

        $content = file_get_contents($this->filePath);
        if ($content === false) {
            $this->logger?->warning('Cannot read pattern file', ['path' => $this->filePath]);
            return [];
        }

        try {
            $data = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            $this->logger?->warning('Pattern file contains invalid JSON', [
                'path' => $this->filePath,
                'error' => $jsonException->getMessage(),
            ]);
            return [];
        }

        if (!is_array($data)) {
            $this->logger?->warning('Pattern file does not contain an array', ['path' => $this->filePath]);
            return [];
        }

        return $this->filterInvalidEntries($data);
    }

    /**
     * Returns the file modification time.
     */
    public function getFileMtime(): int
    {
        $mtime = @filemtime($this->filePath);
        return $mtime !== false ? $mtime : 0;
    }

    /**
     * Reports issues with the on-disk pattern file at the *shape* level only:
     * readability, JSON validity, top-level array, and per-row array shape.
     *
     * Returns null when the file is healthy (or genuinely empty); otherwise a
     * human-readable description of the issue.
     *
     * Semantic checks that depend on knowing what a row means (for example
     * whether `kind` maps to a valid PatternKind) intentionally live in
     * FileArrayPatternBackend::checkIntegrity(), which is the user-facing
     * entry point called by the backend module.
     */
    public function checkFileShape(): ?string
    {
        if (!is_file($this->filePath)) {
            return null;
        }

        $content = file_get_contents($this->filePath);
        if ($content === false) {
            return 'Pattern file cannot be read.';
        }

        $trimmed = trim($content);
        if (in_array($trimmed, ['', '[]', '{}'], true)) {
            return null;
        }

        try {
            $data = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            return sprintf('Pattern file contains invalid JSON: %s', $jsonException->getMessage());
        }

        if (!is_array($data)) {
            return 'Pattern file does not contain an array.';
        }

        $rawCount = count($data);
        $validCount = count($this->filterInvalidEntries($data));
        if ($validCount < $rawCount) {
            return sprintf(
                '%d of %d pattern entries are malformed and were skipped.',
                $rawCount - $validCount,
                $rawCount,
            );
        }

        return null;
    }

    /**
     * @param array<mixed> $data
     * @return array<string, array<string, mixed>>
     */
    private function filterInvalidEntries(array $data): array
    {
        $result = [];
        foreach ($data as $key => $item) {
            if (!is_string($key)) {
                continue;
            }

            if (!is_array($item)) {
                continue;
            }

            if (!$this->isStringIndexedArray($item)) {
                continue;
            }

            $result[$key] = $item;
        }

        return $result;
    }

    /**
     * @param array<mixed> $array
     */
    private function isStringIndexedArray(array $array): bool
    {
        foreach (array_keys($array) as $key) {
            if (!is_string($key)) {
                return false;
            }
        }

        return true;
    }

    public function ensureDirectory(): void
    {
        $directory = dirname($this->filePath);
        if (is_dir($directory)) {
            return;
        }

        if (!@mkdir($directory, 0775, true) && !is_dir($directory)) {
            $this->logger?->warning('Cannot create directory for pattern file', [
                'path' => $this->filePath,
                'directory' => $directory,
            ]);
        }
    }

    /**
     * Writes the array to JSON file.
     *
     * @param array<string, array<string, mixed>> $data
     */
    public function writeArray(array $data): void
    {
        $this->ensureDirectory();

        $lockHandle = $this->acquireExclusiveLock();

        try {
            $this->writeArrayLocked($data);
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
    }

    /**
     * Atomically reads, modifies, and writes the array file while holding an exclusive lock.
     *
     * The modifier callable receives the current data array and must return either:
     * - an array: the new data to write
     * - null: skip writing (no-op signal)
     *
     * @param callable(array<string, array<string, mixed>>): (?array<string, array<string, mixed>>) $modifier
     */
    public function readModifyWrite(callable $modifier): void
    {
        $this->ensureDirectory();
        $lockHandle = $this->acquireExclusiveLock();

        try {
            clearstatcache(true, $this->filePath);
            $data = $this->readArray();
            $result = $modifier($data);

            if ($result === null) {
                return;
            }

            if (!is_array($result)) {
                throw new \LogicException(
                    sprintf('readModifyWrite modifier must return array|null, got %s', get_debug_type($result)),
                    1779133201
                );
            }

            $this->writeArrayLocked($result);
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
    }

    /**
     * Validates that all data values are scalar (prevents object serialization attacks).
     *
     * @param array<string, array<string, mixed>> $data
     */
    private function assertScalarData(array $data): void
    {
        array_walk_recursive($data, static function (mixed $value): void {
            if (!is_scalar($value) && $value !== null) {
                throw new \InvalidArgumentException(
                    sprintf('Only scalar values allowed in pattern data, got %s', get_debug_type($value)),
                    1770238501
                );
            }
        });
    }

    /**
     * Invalidates stat cache after a successful write.
     */
    private function invalidateCaches(): void
    {
        clearstatcache(true, $this->filePath);
        $this->logger?->debug('Pattern file written', ['path' => $this->filePath]);
    }

    /**
     * Opens the lock file and acquires an exclusive lock.
     *
     * @return resource The lock file handle (caller must unlock and close)
     */
    private function acquireExclusiveLock(): mixed
    {
        $lockFile = $this->filePath . '.lock';
        $lockHandle = fopen($lockFile, 'cb');
        if ($lockHandle === false) {
            throw new \RuntimeException(
                sprintf('Cannot create lock file: %s', $lockFile),
                1770238494
            );
        }

        if (!flock($lockHandle, LOCK_EX)) {
            fclose($lockHandle);
            throw new \RuntimeException(
                sprintf('Cannot acquire lock for pattern file: %s', $this->filePath),
                1770238497
            );
        }

        return $lockHandle;
    }

    /**
     * Writes the array to the file. Assumes caller holds the exclusive lock.
     *
     * @param array<string, array<string, mixed>> $data
     */
    private function writeArrayLocked(array $data): void
    {
        $this->assertScalarData($data);

        try {
            $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $jsonException) {
            throw new \RuntimeException(
                sprintf('Cannot encode pattern data to JSON: %s', $jsonException->getMessage()),
                1770238500,
                $jsonException
            );
        }

        $tmp = $this->filePath . '.' . bin2hex(random_bytes(16));

        try {
            if (file_put_contents($tmp, $json) === false) {
                throw new \RuntimeException(
                    sprintf('Cannot write temporary pattern file: %s', $tmp),
                    1770238507
                );
            }

            if (!@rename($tmp, $this->filePath) && file_put_contents($this->filePath, $json) === false) {
                throw new \RuntimeException(
                    sprintf('Cannot write pattern file: %s', $this->filePath),
                    1770238512
                );
            }

            $this->invalidateCaches();
        } finally {
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }
    }
}
