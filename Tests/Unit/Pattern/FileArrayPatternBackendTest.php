<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Pattern;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(FileArrayPatternBackend::class)]
final class FileArrayPatternBackendTest extends TestCase
{
    private string $testDir;

    private string $testFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->testDir = sys_get_temp_dir() . '/typo3_firewall_backend_test_' . bin2hex(random_bytes(8));
        @mkdir($this->testDir, 0777, true);
        $this->testFile = $this->testDir . '/patterns.json';
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

    private function createBackend(?int $now = null): FileArrayPatternBackend
    {
        return new FileArrayPatternBackend(
            $this->testFile,
            new FileArrayWriter($this->testFile),
            null, // logger
            $now
        );
    }

    #[Test]
    public function consumeReturnsEmptySnapshotForNewFile(): void
    {
        $fileArrayPatternBackend = $this->createBackend();

        $patternSnapshot = $fileArrayPatternBackend->consume();

        self::assertCount(0, $patternSnapshot->entries);
        self::assertSame($this->testFile, $patternSnapshot->source);
    }

    #[Test]
    public function appendAddsPatternEntry(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1');

        $fileArrayPatternBackend->append($patternEntry);
        $patternSnapshot = $fileArrayPatternBackend->consume();

        self::assertCount(1, $patternSnapshot->entries);
        self::assertSame(PatternKind::IP, $patternSnapshot->entries[0]->kind);
        self::assertSame('192.168.1.1', $patternSnapshot->entries[0]->value);
    }

    #[Test]
    public function appendUpdatesExistingPatternWithSameKindValueTarget(): void
    {
        $fileArrayPatternBackend = $this->createBackend(1000);
        $entry1 = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1', expiresAt: 2000);
        $entry2 = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1', expiresAt: 3000);

        $fileArrayPatternBackend->append($entry1);
        $fileArrayPatternBackend->append($entry2);

        $patternSnapshot = $fileArrayPatternBackend->consume();

        self::assertCount(1, $patternSnapshot->entries);
        self::assertSame(3000, $patternSnapshot->entries[0]->expiresAt);
    }

    #[Test]
    public function appendGeneratesIdFromHash(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1');

        $fileArrayPatternBackend->append($patternEntry);
        $raw = $fileArrayPatternBackend->listRaw();

        $id = $raw[0]['id'];
        self::assertIsString($id);
        self::assertSame(64, strlen($id)); // SHA256 hash length
    }

    #[Test]
    public function appendUsesProvidedIdFromMetadata(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            metadata: ['id' => 'custom-id-123']
        );

        $fileArrayPatternBackend->append($patternEntry);
        $raw = $fileArrayPatternBackend->listRaw();

        self::assertSame('custom-id-123', $raw[0]['id']);
    }

    #[Test]
    public function removeByIdRemovesPattern(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            metadata: ['id' => 'to-remove']
        );

        $fileArrayPatternBackend->append($patternEntry);
        self::assertCount(1, $fileArrayPatternBackend->listRaw());

        $fileArrayPatternBackend->removeById('to-remove');
        self::assertCount(0, $fileArrayPatternBackend->listRaw());
    }

    #[Test]
    public function removeByIdDoesNothingForNonExistentId(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            metadata: ['id' => 'existing']
        );

        $fileArrayPatternBackend->append($patternEntry);
        $fileArrayPatternBackend->removeById('non-existent');

        self::assertCount(1, $fileArrayPatternBackend->listRaw());
    }

    #[Test]
    public function pruneExpiredRemovesExpiredPatterns(): void
    {
        $now = 1000;
        $fileArrayPatternBackend = $this->createBackend($now);

        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '1.1.1.1', expiresAt: 500)); // expired
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '2.2.2.2', expiresAt: 1500)); // valid
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '3.3.3.3')); // no expiry

        $fileArrayPatternBackend->pruneExpired();

        $raw = $fileArrayPatternBackend->listRaw();

        self::assertCount(2, $raw);
        self::assertSame('2.2.2.2', $raw[0]['value']);
        self::assertSame('3.3.3.3', $raw[1]['value']);
    }

    #[Test]
    public function pruneExpiredDoesNothingWhenNoExpiredPatterns(): void
    {
        $now = 1000;
        $fileArrayPatternBackend = $this->createBackend($now);

        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '1.1.1.1', expiresAt: 2000));

        $fileArrayPatternBackend->pruneExpired();

        self::assertCount(1, $fileArrayPatternBackend->listRaw());
    }

    #[Test]
    public function typeReturnsPhpArray(): void
    {
        $fileArrayPatternBackend = $this->createBackend();

        self::assertSame('php_array', $fileArrayPatternBackend->type());
    }

    #[Test]
    public function capabilitiesReturnsExpectedValues(): void
    {
        $fileArrayPatternBackend = $this->createBackend();

        $capabilities = $fileArrayPatternBackend->capabilities();

        self::assertTrue($capabilities['append']);
        self::assertTrue($capabilities['pruneExpired']);
        self::assertSame('php', $capabilities['format']);
        self::assertSame($this->testFile, $capabilities['path']);
    }

    #[Test]
    public function listRawReturnsAllPatterns(): void
    {
        $fileArrayPatternBackend = $this->createBackend();

        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '1.1.1.1'));
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::CIDR, value: '10.0.0.0/8'));

        $raw = $fileArrayPatternBackend->listRaw();

        self::assertCount(2, $raw);
        self::assertSame('ip', $raw[0]['kind']);
        self::assertSame('cidr', $raw[1]['kind']);
    }

    #[Test]
    public function createStaticMethodCreatesWorkingInstance(): void
    {
        $fileArrayPatternBackend =  new FileArrayPatternBackend($this->testFile, new FileArrayWriter($this->testFile));

        // Verify the instance works by calling a method
        self::assertSame('php_array', $fileArrayPatternBackend->type());
    }

    // Validation tests

    #[Test]
    public function appendThrowsExceptionForEmptyKind(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: '', value: '192.168.1.1');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Pattern kind and value must not be empty');

        $fileArrayPatternBackend->append($patternEntry);
    }

    #[Test]
    public function appendThrowsExceptionForEmptyValue(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Pattern kind and value must not be empty');

        $fileArrayPatternBackend->append($patternEntry);
    }

    #[Test]
    public function appendThrowsExceptionForInvalidKind(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: 'invalid_kind', value: 'test');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid pattern kind: invalid_kind');

        $fileArrayPatternBackend->append($patternEntry);
    }

    #[Test]
    public function appendThrowsExceptionForInvalidIpAddress(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: 'not-an-ip');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address: not-an-ip');

        $fileArrayPatternBackend->append($patternEntry);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validIpAddressProvider(): array
    {
        return [
            'ipv4' => ['192.168.1.1'],
            'ipv4 localhost' => ['127.0.0.1'],
            'ipv4 zeros' => ['0.0.0.0'],
            'ipv6 full' => ['2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
            'ipv6 compressed' => ['2001:db8:85a3::8a2e:370:7334'],
            'ipv6 localhost' => ['::1'],
        ];
    }

    #[Test]
    #[DataProvider('validIpAddressProvider')]
    public function appendAcceptsValidIpAddresses(string $ip): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: $ip);

        $fileArrayPatternBackend->append($patternEntry);

        self::assertCount(1, $fileArrayPatternBackend->listRaw());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidIpAddressProvider(): array
    {
        return [
            'word' => ['localhost'],
            'partial ip' => ['192.168.1'],
            'too many octets' => ['192.168.1.1.1'],
            'out of range' => ['256.1.1.1'],
            'with port' => ['192.168.1.1:80'],
            'cidr notation' => ['192.168.1.0/24'],
        ];
    }

    #[Test]
    #[DataProvider('invalidIpAddressProvider')]
    public function appendRejectsInvalidIpAddresses(string $ip): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: $ip);

        $this->expectException(\InvalidArgumentException::class);
        $fileArrayPatternBackend->append($patternEntry);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validCidrProvider(): array
    {
        return [
            'ipv4 /8' => ['10.0.0.0/8'],
            'ipv4 /16' => ['172.16.0.0/16'],
            'ipv4 /24' => ['192.168.1.0/24'],
            'ipv4 /32' => ['192.168.1.1/32'],
            'ipv4 /0' => ['0.0.0.0/0'],
            'ipv6 /64' => ['2001:db8::/64'],
            'ipv6 /128' => ['::1/128'],
            'ipv6 /0' => ['::/0'],
        ];
    }

    #[Test]
    #[DataProvider('validCidrProvider')]
    public function appendAcceptsValidCidrNotation(string $cidr): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::CIDR, value: $cidr);

        $fileArrayPatternBackend->append($patternEntry);

        self::assertCount(1, $fileArrayPatternBackend->listRaw());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidCidrProvider(): array
    {
        return [
            'no prefix' => ['192.168.1.0'],
            'invalid prefix ipv4' => ['192.168.1.0/33'],
            'invalid prefix ipv6' => ['2001:db8::/129'],
            'negative prefix' => ['192.168.1.0/-1'],
            'non-numeric prefix' => ['192.168.1.0/abc'],
            'invalid ip in cidr' => ['999.168.1.0/24'],
            'double slash' => ['192.168.1.0//24'],
        ];
    }

    #[Test]
    #[DataProvider('invalidCidrProvider')]
    public function appendRejectsInvalidCidrNotation(string $cidr): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::CIDR, value: $cidr);

        $this->expectException(\InvalidArgumentException::class);
        $fileArrayPatternBackend->append($patternEntry);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validRegexProvider(): array
    {
        return [
            'simple' => ['/admin/'],
            'with modifiers' => ['/admin/i'],
            'with groups' => ['/(admin|wp-admin)/'],
            'with anchors' => ['/^\/admin$/'],
            'complex' => ['/^\/api\/v[0-9]+\/.*/i'],
        ];
    }

    #[Test]
    #[DataProvider('validRegexProvider')]
    public function appendAcceptsValidRegexPatterns(string $regex): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::PATH_REGEX, value: $regex);

        $fileArrayPatternBackend->append($patternEntry);

        self::assertCount(1, $fileArrayPatternBackend->listRaw());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidRegexProvider(): array
    {
        return [
            'unmatched bracket' => ['/[admin/'],
            'unmatched paren' => ['/(admin/'],
            'invalid modifier' => ['/admin/z'],
            'no delimiters' => ['admin'],
        ];
    }

    #[Test]
    #[DataProvider('invalidRegexProvider')]
    public function appendRejectsInvalidRegexPatterns(string $regex): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::PATH_REGEX, value: $regex);

        $this->expectException(\InvalidArgumentException::class);
        $fileArrayPatternBackend->append($patternEntry);
    }

    #[Test]
    public function appendThrowsExceptionWhenMaxEntriesExceeded(): void
    {
        // Write max entries directly to file as JSON with id-indexed structure
        $data = [];
        for ($i = 0; $i < 10000; $i++) {
            $data['id-' . $i] = ['kind' => 'ip', 'value' => '1.1.1.1'];
        }

        file_put_contents($this->testFile, json_encode($data));

        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Pattern file exceeds maximum entries (10000)');

        $fileArrayPatternBackend->append($patternEntry);
    }

    #[Test]
    public function appendSetsAddedAtTimestamp(): void
    {
        $now = 1704067200;
        $fileArrayPatternBackend = $this->createBackend($now);
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1');

        $fileArrayPatternBackend->append($patternEntry);
        $raw = $fileArrayPatternBackend->listRaw();

        self::assertSame($now, $raw[0]['addedAt']);
    }

    #[Test]
    public function appendPreservesExistingAddedAt(): void
    {
        $now = 1704067200;
        $fileArrayPatternBackend = $this->createBackend($now);
        $patternEntry = new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1', addedAt: 1704000000);

        $fileArrayPatternBackend->append($patternEntry);
        $raw = $fileArrayPatternBackend->listRaw();

        self::assertSame(1704000000, $raw[0]['addedAt']);
    }

    #[Test]
    public function consumeReturnsPatternSnapshotWithCorrectVersion(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::IP, value: '1.1.1.1'));

        $patternSnapshot = $fileArrayPatternBackend->consume();

        // version is the file mtime
        self::assertGreaterThan(0, $patternSnapshot->version);
    }

    #[Test]
    public function appendWithTargetForHeaderPattern(): void
    {
        $fileArrayPatternBackend = $this->createBackend();
        $patternEntry = new PatternEntry(
            kind: PatternKind::HEADER_EXACT,
            value: 'BadBot',
            target: 'User-Agent'
        );

        $fileArrayPatternBackend->append($patternEntry);
        $patternSnapshot = $fileArrayPatternBackend->consume();

        self::assertSame('User-Agent', $patternSnapshot->entries[0]->target);
    }
}
