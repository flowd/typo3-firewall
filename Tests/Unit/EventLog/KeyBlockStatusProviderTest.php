<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\EventLog;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\EventLog\KeyBlockStatus;
use Flowd\Typo3Firewall\EventLog\KeyBlockStatusProvider;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(KeyBlockStatusProvider::class)]
final class KeyBlockStatusProviderTest extends TestCase
{
    private string $patternsFilePath;

    private KeyHasher $keyHasher;

    private mixed $originalConfVars;

    protected function setUp(): void
    {
        parent::setUp();
        vfsStream::setup('root');
        $this->patternsFilePath = vfsStream::url('root') . '/patterns.json';
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

    private function createProvider(?Config $config = null): KeyBlockStatusProvider
    {
        return new KeyBlockStatusProvider(
            $config ?? new Config(new InMemoryCache()),
            $this->keyHasher,
            FileArrayPatternBackend::forFile($this->patternsFilePath),
        );
    }

    private function createConfigWithFail2BanRule(string $ruleName): Config
    {
        $config = new Config(new InMemoryCache());
        $config->fail2ban->add(
            name: $ruleName,
            threshold: 5,
            period: 60,
            ban: 3600,
            filter: static fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/login',
        );

        return $config;
    }

    #[Test]
    public function aBannedKeyIsReportedWithItsRuleAndBanType(): void
    {
        $config = $this->createConfigWithFail2BanRule('login');
        $config->banManager()->ban('login', '203.0.113.10', 3600, BanType::Fail2Ban);

        $status = $this->createProvider($config)->findBlockStatus($this->keyHasher->hash('203.0.113.10'), '203.0.113.10');

        self::assertInstanceOf(KeyBlockStatus::class, $status);
        self::assertSame(KeyBlockStatus::SOURCE_BAN, $status->source);
        self::assertSame('login (fail2ban)', $status->detail);
    }

    #[Test]
    public function aBannedNonIpKeyIsReportedViaItsHashAlone(): void
    {
        $config = $this->createConfigWithFail2BanRule('api-abuse');
        $config->banManager()->ban('api-abuse', 'api-token-value', 3600, BanType::Fail2Ban);

        $status = $this->createProvider($config)->findBlockStatus($this->keyHasher->hash('api-token-value'), '');

        self::assertInstanceOf(KeyBlockStatus::class, $status);
        self::assertSame(KeyBlockStatus::SOURCE_BAN, $status->source);
    }

    #[Test]
    public function anIpPatternEntryIsReportedEvenWithoutAReadableDisplay(): void
    {
        FileArrayPatternBackend::forFile($this->patternsFilePath)
            ->append(new PatternEntry(kind: PatternKind::IP, value: '203.0.113.10'));

        $status = $this->createProvider()->findBlockStatus($this->keyHasher->hash('203.0.113.10'), '');

        self::assertInstanceOf(KeyBlockStatus::class, $status);
        self::assertSame(KeyBlockStatus::SOURCE_PATTERN, $status->source);
        self::assertSame('ip 203.0.113.10', $status->detail);
    }

    #[Test]
    public function aCidrPatternEntryMatchesTheReadableDisplayIp(): void
    {
        FileArrayPatternBackend::forFile($this->patternsFilePath)
            ->append(new PatternEntry(kind: PatternKind::CIDR, value: '203.0.113.0/24'));

        $status = $this->createProvider()->findBlockStatus($this->keyHasher->hash('203.0.113.77'), '203.0.113.77');

        self::assertInstanceOf(KeyBlockStatus::class, $status);
        self::assertSame('cidr 203.0.113.0/24', $status->detail);
    }

    #[Test]
    public function aCidrFinerThanTheAnonymizationMaskIsOnlyDecidedForFullIps(): void
    {
        FileArrayPatternBackend::forFile($this->patternsFilePath)
            ->append(new PatternEntry(kind: PatternKind::CIDR, value: '203.0.113.0/25'));

        $keyBlockStatusProvider = $this->createProvider();

        self::assertNull(
            $keyBlockStatusProvider->findBlockStatus($this->keyHasher->hash('203.0.113.10'), '203.0.113.0'),
            'An anonymized network address cannot decide a /25 match for the real client IP',
        );
        self::assertInstanceOf(
            KeyBlockStatus::class,
            $keyBlockStatusProvider->findBlockStatus($this->keyHasher->hash('203.0.113.10'), '203.0.113.10'),
        );
    }

    #[Test]
    public function aCompleteZeroHostKeyIsDecidedAgainstFineCidrEntries(): void
    {
        FileArrayPatternBackend::forFile($this->patternsFilePath)
            ->append(new PatternEntry(kind: PatternKind::CIDR, value: '203.0.113.0/25'));

        $status = $this->createProvider()->findBlockStatus($this->keyHasher->hash('203.0.113.0'), '203.0.113.0');

        self::assertInstanceOf(KeyBlockStatus::class, $status, 'A display matching its key hash is the complete key, so fine CIDR entries are decidable');
    }

    #[Test]
    public function anUnknownKeyAndAnEmptyHashReportNoStatus(): void
    {
        $keyBlockStatusProvider = $this->createProvider();

        self::assertNull($keyBlockStatusProvider->findBlockStatus($this->keyHasher->hash('198.51.100.1'), '198.51.100.1'));
        self::assertNull($keyBlockStatusProvider->findBlockStatus('', ''));
    }
}
