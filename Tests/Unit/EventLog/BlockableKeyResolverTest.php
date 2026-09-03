<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\EventLog\BlockableKeyResolver;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(BlockableKeyResolver::class)]
final class BlockableKeyResolverTest extends TestCase
{
    private KeyHasher $keyHasher;

    private mixed $originalConfVars;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalConfVars = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['encryptionKey' => 'unit-test-encryption-key']];
        $this->keyHasher = new KeyHasher();
    }

    protected function tearDown(): void
    {
        if ($this->originalConfVars === null) {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        } else {
            $GLOBALS['TYPO3_CONF_VARS'] = $this->originalConfVars;
        }

        parent::tearDown();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function completeKeyDisplays(): array
    {
        return [
            'full IPv4' => ['203.0.113.10'],
            'full IPv4 with zero host bits' => ['203.0.113.0'],
            'full IPv6' => ['2001:db8::1'],
            'full IPv6 network-like address' => ['2001:db8:1:2::'],
        ];
    }

    #[Test]
    #[DataProvider('completeKeyDisplays')]
    public function aDisplayMatchingTheKeyHashResolvesToAnExactIpEntry(string $keyDisplay): void
    {
        $patternEntry = (new BlockableKeyResolver($this->keyHasher))
            ->resolve($keyDisplay, $this->keyHasher->hash($keyDisplay));

        self::assertInstanceOf(PatternEntry::class, $patternEntry);
        self::assertSame(PatternKind::IP, $patternEntry->kind);
        self::assertSame($keyDisplay, $patternEntry->value);
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function unresolvableDisplays(): array
    {
        return [
            'anonymized address, hash of the real key' => ['203.0.113.0', '203.0.113.10'],
            'anonymized IPv6 address' => ['2001:db8:1:2::', '2001:db8:1:2::af'],
            'non-IP display' => ['not-an-ip', 'not-an-ip'],
        ];
    }

    #[Test]
    #[DataProvider('unresolvableDisplays')]
    public function aDisplayNotMatchingTheKeyHashResolvesToNull(string $keyDisplay, string $realKey): void
    {
        self::assertNull(
            (new BlockableKeyResolver($this->keyHasher))->resolve($keyDisplay, $this->keyHasher->hash($realKey)),
        );
    }

    #[Test]
    public function aHashOnlyKeyResolvesToNull(): void
    {
        self::assertNull((new BlockableKeyResolver($this->keyHasher))->resolve('', $this->keyHasher->hash('api-token')));
        self::assertNull((new BlockableKeyResolver($this->keyHasher))->resolve('203.0.113.10', ''));
    }
}
