<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Writer;

use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(FileArrayWriter::class)]
final class FileArrayWriterTest extends TestCase
{
    private string $testDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->testDir = sys_get_temp_dir() . '/typo3_firewall_test_' . bin2hex(random_bytes(8));
        @mkdir($this->testDir, 0777, true);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->removeDirectory($this->testDir);
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $scanned = scandir($dir);
        $files = array_diff($scanned !== false ? $scanned : [], ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->removeDirectory($path) : @unlink($path);
        }

        @rmdir($dir);
    }

    #[Test]
    public function readArrayReturnsEmptyArrayForNonExistentFile(): void
    {
        $fileArrayWriter = new FileArrayWriter($this->testDir . '/nonexistent.php');

        self::assertSame([], $fileArrayWriter->readArray());
    }

    #[Test]
    public function writeArrayCreatesFileWithValidJson(): void
    {
        $filePath = $this->testDir . '/test.json';
        $fileArrayWriter = new FileArrayWriter($filePath);
        $data = [
            'id-1' => ['kind' => 'ip', 'value' => '192.168.1.1'],
            'id-2' => ['kind' => 'cidr', 'value' => '10.0.0.0/8'],
        ];

        $fileArrayWriter->writeArray($data);

        self::assertFileExists($filePath);
        $content = file_get_contents($filePath);
        self::assertIsString($content);
        $result = json_decode($content, true);
        self::assertSame($data, $result);
    }

    #[Test]
    public function readArrayReturnsWrittenData(): void
    {
        $filePath = $this->testDir . '/test.json';
        $fileArrayWriter = new FileArrayWriter($filePath);
        $data = [
            'id-1' => ['kind' => 'ip', 'value' => '192.168.1.1'],
        ];

        $fileArrayWriter->writeArray($data);
        $result = $fileArrayWriter->readArray();

        self::assertSame($data, $result);
    }

    #[Test]
    public function writeArrayOverwritesExistingData(): void
    {
        $filePath = $this->testDir . '/test.php';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $data1 = ['id-1' => ['kind' => 'ip', 'value' => '192.168.1.1']];
        $fileArrayWriter->writeArray($data1);

        $data2 = ['id-2' => ['kind' => 'cidr', 'value' => '10.0.0.0/8']];
        $fileArrayWriter->writeArray($data2);

        $result = $fileArrayWriter->readArray();
        self::assertSame($data2, $result);
    }

    #[Test]
    public function ensureFileExistsCreatesEmptyArrayFile(): void
    {
        $filePath = $this->testDir . '/ensure.json';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $fileArrayWriter->ensureFileExists();

        self::assertFileExists($filePath);
        $content = file_get_contents($filePath);
        self::assertIsString($content);
        $result = json_decode($content, true);
        self::assertSame([], $result);
    }

    #[Test]
    public function ensureFileExistsDoesNotOverwriteExistingFile(): void
    {
        $filePath = $this->testDir . '/existing.json';
        $fileArrayWriter = new FileArrayWriter($filePath);
        $data = ['id-1' => ['kind' => 'ip', 'value' => '192.168.1.1']];
        $fileArrayWriter->writeArray($data);

        $fileArrayWriter->ensureFileExists();

        self::assertSame($data, $fileArrayWriter->readArray());
    }

    #[Test]
    public function ensureDirectoryCreatesNestedDirectories(): void
    {
        $filePath = $this->testDir . '/nested/deep/path/file.php';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $fileArrayWriter->ensureDirectory();

        self::assertDirectoryExists(dirname($filePath));
    }

    #[Test]
    public function readArrayFiltersInvalidEntries(): void
    {
        $filePath = $this->testDir . '/invalid.json';
        // Mix valid id-indexed entries with invalid ones
        $content = json_encode([
            'id-1' => ['kind' => 'ip', 'value' => '1.1.1.1'],  // valid
            'id-2' => 'invalid_string',  // invalid: value is string not array
            'id-3' => [0 => 'numeric_key'],  // invalid: numeric keys in value
        ]);
        file_put_contents($filePath, $content);

        $fileArrayWriter = new FileArrayWriter($filePath);
        $result = $fileArrayWriter->readArray();

        self::assertCount(1, $result);
        self::assertArrayHasKey('id-1', $result);
        self::assertSame('ip', $result['id-1']['kind']);
    }

    #[Test]
    public function readArrayReturnsEmptyArrayForInvalidJsonFile(): void
    {
        $filePath = $this->testDir . '/invalid.json';
        file_put_contents($filePath, 'not valid json {{{');

        $fileArrayWriter = new FileArrayWriter($filePath);
        $result = $fileArrayWriter->readArray();

        self::assertSame([], $result);
    }

    #[Test]
    public function readArrayReturnsEmptyArrayForNonArrayJson(): void
    {
        $filePath = $this->testDir . '/string.json';
        file_put_contents($filePath, '"just a string"');

        $fileArrayWriter = new FileArrayWriter($filePath);
        $result = $fileArrayWriter->readArray();

        self::assertSame([], $result);
    }

    #[Test]
    public function getFileMtimeReturnsZeroForNonExistentFile(): void
    {
        $fileArrayWriter = new FileArrayWriter($this->testDir . '/nonexistent.php');

        self::assertSame(0, $fileArrayWriter->getFileMtime());
    }

    #[Test]
    public function getFileMtimeReturnsValidTimestamp(): void
    {
        $filePath = $this->testDir . '/mtime.php';
        $fileArrayWriter = new FileArrayWriter($filePath);
        $fileArrayWriter->writeArray([]);

        $mtime = $fileArrayWriter->getFileMtime();

        self::assertGreaterThan(0, $mtime);
        self::assertLessThanOrEqual(time(), $mtime);
    }

    #[Test]
    public function writeArrayCleansUpTempFilesOnSuccess(): void
    {
        $filePath = $this->testDir . '/cleanup.json';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $fileArrayWriter->writeArray(['id-1' => ['kind' => 'ip', 'value' => '1.1.1.1']]);

        // Check no temp files remain
        $files = glob($this->testDir . '/cleanup.json.*');
        self::assertEmpty($files);
    }

    #[Test]
    public function writeArrayRejectsNonScalarData(): void
    {
        $filePath = $this->testDir . '/scalar.json';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only scalar values allowed');

        $fileArrayWriter->writeArray(['id-1' => ['object' => new \stdClass()]]);
    }

    /**
     * @return array<string, array{0: array<string, array<string, mixed>>, 1: int}>
     */
    public static function validArrayDataProvider(): array
    {
        return [
            'empty array' => [[], 0],
            'single entry' => [['id-1' => ['kind' => 'ip', 'value' => '1.1.1.1']], 1],
            'multiple entries' => [
                [
                    'id-1' => ['kind' => 'ip', 'value' => '1.1.1.1'],
                    'id-2' => ['kind' => 'cidr', 'value' => '10.0.0.0/8'],
                    'id-3' => ['kind' => 'path_prefix', 'value' => '/admin'],
                ],
                3,
            ],
            'entry with metadata' => [
                ['id-1' => ['kind' => 'ip', 'value' => '1.1.1.1', 'metadata' => ['note' => 'test']]],
                1,
            ],
        ];
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    #[Test]
    #[DataProvider('validArrayDataProvider')]
    public function writeAndReadPreservesData(array $data, int $expectedCount): void
    {
        $filePath = $this->testDir . '/data.php';
        $fileArrayWriter = new FileArrayWriter($filePath);

        $fileArrayWriter->writeArray($data);

        $result = $fileArrayWriter->readArray();

        self::assertCount($expectedCount, $result);
        self::assertSame($data, $result);
    }
}
