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
    }

    #[Test]
    public function constructorAcceptsAllParameters(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
            target: 'User-Agent',
            expiresAt: '2025-12-31 23:59:59',
        );

        self::assertSame('ip', $patternEntryDto->kind);
        self::assertSame('192.168.1.1', $patternEntryDto->value);
        self::assertSame('User-Agent', $patternEntryDto->target);
        self::assertSame('2025-12-31 23:59:59', $patternEntryDto->expiresAt);
    }

    #[Test]
    public function toPatternEntryReturnsPatternEntry(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
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

        self::assertSame(PatternKind::IP, $patternEntry->kind);
        self::assertSame('192.168.1.1', $patternEntry->value);
        self::assertSame('User-Agent', $patternEntry->target);
    }

    #[Test]
    public function toPatternEntryThrowsForUnknownKind(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'not_a_kind',
            value: '192.168.1.1'
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid pattern kind: not_a_kind');

        $patternEntryDto->toPatternEntry();
    }

    #[Test]
    public function toPatternEntryThrowsForEmptyKind(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: '',
            value: '192.168.1.1'
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid pattern kind:');

        $patternEntryDto->toPatternEntry();
    }

    #[Test]
    public function toPatternEntryParsesValidExpiresAt(): void
    {
        // Use a date far in the future to ensure it's always valid
        $futureDate = date('Y-m-d H:i:s', strtotime('+1 year'));
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
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
            kind: 'ip',
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
            kind: 'ip',
            value: '192.168.1.1',
            expiresAt: '   '
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->expiresAt);
    }

    #[Test]
    public function toPatternEntryThrowsForInvalidExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
            expiresAt: 'not-a-date'
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid expiration date: not-a-date');

        $patternEntryDto->toPatternEntry();
    }

    #[Test]
    public function toPatternEntryThrowsForPastExpiresAt(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
            expiresAt: '2020-01-01 00:00:00'
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Expiration date must be in the future');

        $patternEntryDto->toPatternEntry();
    }

    #[Test]
    public function toPatternEntryProducesEmptyMetadata(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertSame([], $patternEntry->metadata);
        self::assertNull($patternEntry->addedAt);
    }

    #[Test]
    public function toPatternEntryHandlesNullTarget(): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1'
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNull($patternEntry->target);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validExpiresAtFormatProvider(): array
    {
        $futureYear = (int)date('Y') + 1;
        return [
            'ISO 8601' => [$futureYear . '-12-31T23:59:59'],
            'MySQL datetime' => [$futureYear . '-12-31 23:59:59'],
            'relative future' => ['+1 month'],
            'date only future' => [$futureYear . '-12-31'],
        ];
    }

    #[Test]
    #[DataProvider('validExpiresAtFormatProvider')]
    public function toPatternEntryAcceptsValidFutureDates(string $expiresAt): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
            expiresAt: $expiresAt
        );

        $patternEntry = $patternEntryDto->toPatternEntry();

        self::assertNotNull($patternEntry->expiresAt);
        self::assertGreaterThan(time(), $patternEntry->expiresAt);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function pastExpiresAtFormatProvider(): array
    {
        return [
            'relative past' => ['-1 day'],
            'date only past' => ['2020-01-01'],
        ];
    }

    #[Test]
    #[DataProvider('pastExpiresAtFormatProvider')]
    public function toPatternEntryRejectsPastDates(string $expiresAt): void
    {
        $patternEntryDto = new PatternEntryDto(
            kind: 'ip',
            value: '192.168.1.1',
            expiresAt: $expiresAt
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Expiration date must be in the future');

        $patternEntryDto->toPatternEntry();
    }

    #[Test]
    public function propertiesArePublicAndMutable(): void
    {
        $patternEntryDto = new PatternEntryDto();

        $patternEntryDto->kind = 'cidr';
        $patternEntryDto->value = '10.0.0.0/8';
        $patternEntryDto->target = 'X-Custom-Header';
        $patternEntryDto->expiresAt = '+1 week';

        self::assertSame('cidr', $patternEntryDto->kind);
        self::assertSame('10.0.0.0/8', $patternEntryDto->value);
        self::assertSame('X-Custom-Header', $patternEntryDto->target);
        self::assertSame('+1 week', $patternEntryDto->expiresAt);
    }
}
