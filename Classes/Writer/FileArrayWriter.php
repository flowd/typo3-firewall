<?php

namespace Flowd\Typo3Firewall\Writer;

use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * @internal
 */
final class FileArrayWriter
{
    public function __construct(private readonly string $filePath) {}

    public function ensureFileExists(): void
    {
        if (!@is_file($this->filePath)) {
            $this->writeArray([]);
        }
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function readArray(): array
    {
        if (!@is_file($this->filePath)) {
            return [];
        }

        $data = @include $this->filePath;
        if (!\is_array($data)) {
            return [];
        }

        return $this->filterInvalidEntries($data);
    }

    /**
     * @param array<mixed> $data
     * @return list<array<string, mixed>>
     */
    private function filterInvalidEntries(array $data): array
    {
        /** @var list<array<string, mixed>> $values */
        $values = array_filter($data, function (mixed $item): bool {
            if (!is_array($item)) {
                return false;
            }

            return $this->isStringIndexedArray($item);
        });
        return array_values($values);
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
     * @param list<array<string, mixed>> $data
     */
    public function writeArray(array $data): void
    {
        $this->ensureDirectory();
        $tmp = $this->filePath . '.tmp';
        $php = "<?php\nreturn " . var_export($data, true) . ";\n";
        GeneralUtility::writeFile($tmp, $php);
        if (!@rename($tmp, $this->filePath) && @file_put_contents($this->filePath, $php) === false) {
            throw new \RuntimeException(sprintf('Cannot write pattern file: %s', $this->filePath), 4649000086);
        }
    }
}
