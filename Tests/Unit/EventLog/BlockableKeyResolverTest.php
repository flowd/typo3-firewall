<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\EventLog\BlockableKeyResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(BlockableKeyResolver::class)]
final class BlockableKeyResolverTest extends TestCase
{
    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function blockableDisplays(): array
    {
        return [
            'full IPv4 becomes an exact ip entry' => ['203.0.113.10', '203.0.113.10'],
            'full IPv6 becomes an exact ip entry' => ['2001:db8::1', '2001:db8::1'],
        ];
    }

    #[Test]
    #[DataProvider('blockableDisplays')]
    public function fullIpDisplaysResolveToAnExactIpEntry(string $keyDisplay, string $expectedValue): void
    {
        $patternEntry = (new BlockableKeyResolver())->resolve($keyDisplay);

        self::assertInstanceOf(PatternEntry::class, $patternEntry);
        self::assertSame(PatternKind::IP, $patternEntry->kind);
        self::assertSame($expectedValue, $patternEntry->value);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function unresolvableDisplays(): array
    {
        return [
            'hash-only key without readable display' => [''],
            'non-IP display' => ['not-an-ip'],
            'anonymized IPv4 network address' => ['203.0.113.0'],
            'anonymized IPv6 network address' => ['2001:db8:1:2::'],
        ];
    }

    #[Test]
    #[DataProvider('unresolvableDisplays')]
    public function displaysWithoutAUsableIpResolveToNull(string $keyDisplay): void
    {
        self::assertNull((new BlockableKeyResolver())->resolve($keyDisplay));
    }
}
