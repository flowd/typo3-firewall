<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Writer;

use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;

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
        GeneralUtility::mkdir_deep(dirname($this->filePath));
    }

    /**
     * Writes the array to JSON file.
     *
     * @param array<string, array<string, mixed>> $data
     */
    public function writeArray(array $data): void
    {
        $this->assertScalarData($data);
        $this->ensureDirectory();

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
            $this->writeWithLock($tmp, $json);
            $this->invalidateCaches();
        } finally {
            if (is_file($tmp)) {
                @unlink($tmp);
            }
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

    private function writeWithLock(string $tmpFile, string $content): void
    {
        if (!GeneralUtility::writeFile($tmpFile, $content)) {
            throw new \RuntimeException(
                sprintf('Cannot write temporary pattern file: %s', $tmpFile),
                1770238507
            );
        }

        $lockFile = $this->filePath . '.lock';
        $lockHandle = fopen($lockFile, 'c');
        if ($lockHandle === false) {
            throw new \RuntimeException(
                sprintf('Cannot create lock file: %s', $lockFile),
                1770238494
            );
        }

        try {
            if (!flock($lockHandle, LOCK_EX)) {
                throw new \RuntimeException(
                    sprintf('Cannot acquire lock for pattern file: %s', $this->filePath),
                    1770238497
                );
            }

            if (!@rename($tmpFile, $this->filePath) && file_put_contents($this->filePath, $content) === false) {
                throw new \RuntimeException(
                    sprintf('Cannot write pattern file: %s', $this->filePath),
                    1770238512
                );
            }

            $this->logger?->debug('Pattern file written successfully', ['path' => $this->filePath]);
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            @unlink($lockFile);
        }
    }
}
