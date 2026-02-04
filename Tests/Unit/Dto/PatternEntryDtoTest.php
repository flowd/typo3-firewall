<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Dto;

use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PatternEntryDto::class)]
final class PatternEntryDtoTest extends TestCase
{
    #[Test]
    public function constructorSetsDefaultValues(): void
    {
        $patternEntryDto = new PatternEntryDto();

        self::assertSame('', $patternEntryDto->kind);
        self::assertSame('', $patternEntryDto->value);
        self::assertNull($patternEntryDto->target);
        self::assertNull($patternEntryDto->expiresAt);
        self::assertNull($patternEntryDto->addedAt);
        self::assertSame([], $patternEntryDto->metadata);
    }

    #[Test]
    public function constructorAcceptsAllParameters(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            target: 'User-Agent',
            expiresAt: '2025-12-31 23:59:59',
            addedAt: 1704067200,
            metadata: ['note' => 'test']
        );

        self::assertSame(PatternKind::IP, $patternEntryDto->kind);
        self::assertSame('192.168.1.1', $patternEntryDto->value);
        self::assertSame('User-Agent', $patternEntryDto->target);
        self::assertSame('2025-12-31 23:59:59', $patternEntryDto->expiresAt);
        self::assertSame(1704067200, $patternEntryDto->addedAt);
        self::assertSame(['note' => 'test'], $patternEntryDto->metadata);
    }

    #[Test]
    public function toPatternEntryReturnsPatternEntry(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1'
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertSame(PatternKind::IP, $patternEntry->kind);
        self::assertSame('192.168.1.1', $patternEntry->value);
    }

    #[Test]
    public function toPatternEntryTrimsWhitespace(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: '  ip  ',
            value: '  192.168.1.1  ',
            target: '  User-Agent  '
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertSame('ip', $patternEntry->kind);
        self::assertSame('192.168.1.1', $patternEntry->value);
        self::assertSame('User-Agent', $patternEntry->target);
    }

    #[Test]
    public function toPatternEntryParsesValidExpiresAt(): void
    {
        // Use a date far in the future to ensure it's always valid
        $futureDate = date('Y-m-d H:i:s', strtotime('+1 year'));
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: $futureDate
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNotNull($patternEntry->expiresAt);
        self::assertGreaterThan(time(), $patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryReturnsNullForEmptyExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: ''
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryReturnsNullForWhitespaceExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: '   '
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryReturnsNullForInvalidExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: 'not-a-date'
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryReturnsNullForPastExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: '2020-01-01 00:00:00'
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryPreservesAddedAt(): void
    {
        $addedAt = 1704067200;
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            addedAt: $addedAt
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertSame($addedAt, $patternEntry->addedAt);
    }

    #[Test]
    public function toPatternEntryPreservesMetadata(): void
    {
        $metadata = ['note' => 'test', 'source' => 'backend'];
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            metadata: $metadata
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertSame($metadata, $patternEntry->metadata);
    }

    #[Test]
    public function toPatternEntryHandlesNullTarget(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            target: null
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->target);
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function expiresAtDateFormatProvider(): array
    {
        $futureYear = (int)date('Y') + 1;
        return [
            'ISO 8601' => [$futureYear . '-12-31T23:59:59', true],
            'MySQL datetime' => [$futureYear . '-12-31 23:59:59', true],
            'relative future' => ['+1 month', true],
            'relative past' => ['-1 day', false],
            'date only future' => [$futureYear . '-12-31', true],
            'date only past' => ['2020-01-01', false],
        ];
    }

    #[Test]
    #[DataProvider('expiresAtDateFormatProvider')]
    public function toPatternEntryHandlesVariousDateFormats(string $expiresAt, bool $shouldBeValid): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: PatternKind::IP,
            value: '192.168.1.1',
            expiresAt: $expiresAt
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        if ($shouldBeValid) {
            self::assertNotNull($patternEntry->expiresAt);
            self::assertGreaterThan(time(), $patternEntry->expiresAt);
        } else {
            self::assertNull($patternEntry->expiresAt);
        }
    }

    #[Test]
    public function propertiesArePublicAndMutable(): void
    {
        $patternEntryDto = new PatternEntryDto();

        $patternEntryDto->kind = PatternKind::CIDR;
        $patternEntryDto->value = '10.0.0.0/8';
        $patternEntryDto->target = 'X-Custom-Header';
        $patternEntryDto->expiresAt = '+1 week';
        $patternEntryDto->addedAt = 1704067200;
        $patternEntryDto->metadata = ['key' => 'value'];

        self::assertSame(PatternKind::CIDR, $patternEntryDto->kind);
        self::assertSame('10.0.0.0/8', $patternEntryDto->value);
        self::assertSame('X-Custom-Header', $patternEntryDto->target);
        self::assertSame('+1 week', $patternEntryDto->expiresAt);
        self::assertSame(1704067200, $patternEntryDto->addedAt);
        self::assertSame(['key' => 'value'], $patternEntryDto->metadata);
    }
}
