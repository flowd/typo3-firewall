<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\EventLog;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Events\Allow2BanBlocked;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBlocked;
use Flowd\Phirewall\Events\Fail2BanMatched;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Typo3Firewall\Command\PruneEventLogCommand;
use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Flowd\Typo3Firewall\EventLog\FirewallEventType;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Console\CommandRegistry;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(EventLogger::class)]
final class EventLogTest extends FunctionalTestCase
{
    /** Mirrors the eventLogTypes default in ext_conf_template.txt. */
    private const string DEFAULT_EVENT_LOG_TYPES = 'blocklist_matched,throttle_exceeded,fail2ban_matched,fail2ban_banned,allow2ban_banned,firewall_error';

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    #[Test]
    public function blocklistMatchedEventIsLogged(): void
    {
        $serverRequest = (new ServerRequest('https://example.com/wp-admin/setup.php', 'GET'))
            ->withAddedHeader('User-Agent', 'sqlmap/1.0');

        $this->dispatch(new BlocklistMatched('scanner-paths', $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('blocklist_matched', $rows[0]['event_type']);
        self::assertSame('scanner-paths', $rows[0]['rule']);
        self::assertSame('example.com', $rows[0]['request_host']);
        self::assertSame('/wp-admin/setup.php', $rows[0]['request_path']);
        self::assertSame('GET', $rows[0]['request_method']);
        self::assertSame('sqlmap/1.0', $rows[0]['user_agent']);
        self::assertGreaterThan(0, $rows[0]['created_at']);
    }

    #[Test]
    public function theRequestPathIncludesTheQueryString(): void
    {
        $serverRequest = new ServerRequest('https://example.com/index.php?id=1&mode=drop', 'GET');

        $this->dispatch(new BlocklistMatched('scanner-paths', $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('/index.php?id=1&mode=drop', $rows[0]['request_path']);
    }

    #[Test]
    public function postParametersAreStoredMaskedAndBoundedInTheMeta(): void
    {
        $serverRequest = (new ServerRequest('https://example.com/login', 'POST'))
            ->withParsedBody([
                'username' => 'administrator',
                'pass' => 'hunter2',
                'code' => 'abc',
                'form' => ['field' => 'value'],
            ]);

        $this->dispatch(new Fail2BanMatched('login-brute-force', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertSame([
            'username' => 'ad***or',
            'pass' => '***',
            'code' => '***',
            'form' => ['field' => 'va***ue'],
        ], $meta['post']);
        self::assertStringNotContainsString('hunter2', $rows[0]['meta']);
        self::assertStringNotContainsString('administrator', $rows[0]['meta']);
    }

    #[Test]
    public function largeFormsAreTruncatedWithASkippedMarker(): void
    {
        $parameters = [];
        for ($i = 1; $i <= 25; ++$i) {
            $parameters['field' . $i] = 'value' . $i;
        }

        $serverRequest = (new ServerRequest('https://example.com/form', 'POST'))->withParsedBody($parameters);

        $this->dispatch(new Fail2BanMatched('form-flood', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertIsArray($meta['post']);
        self::assertCount(21, $meta['post']);
        self::assertSame('5 more parameters', $meta['post']['_skipped']);
        self::assertArrayNotHasKey('field21', $meta['post']);
    }

    #[Test]
    public function postParameterValuesAreStoredInClearTextWhenMaskingIsDisabled(): void
    {
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES, 'eventLogMaskParameters' => '0']);

        try {
            $serverRequest = (new ServerRequest('https://example.com/login', 'POST'))
                ->withParsedBody([
                    'username' => 'administrator',
                    'pass' => 'hunter2',
                    'comment' => str_repeat('a', 300),
                ]);

            $this->dispatch(new Fail2BanMatched('login-brute-force', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

            $rows = $this->fetchAllEventRows();
            self::assertCount(1, $rows);
            self::assertIsString($rows[0]['meta']);
            $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($meta);
            self::assertSame([
                'username' => 'administrator',
                'pass' => '***',
                'comment' => str_repeat('a', 256),
            ], $meta['post']);
            self::assertStringNotContainsString('hunter2', $rows[0]['meta']);
        } finally {
            $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES]);
        }
    }

    #[Test]
    public function throttleExceededEventStoresHashAndAnonymizedIpAndMeta(): void
    {
        $serverRequest = new ServerRequest('https://example.com/search', 'GET');

        $this->dispatch(new ThrottleExceeded('search-throttle', '203.0.113.10', 10, 60, 11, 42, $serverRequest, null));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('throttle_exceeded', $rows[0]['event_type']);
        self::assertSame($this->keyHash('203.0.113.10'), $rows[0]['key_hash']);
        self::assertSame('203.0.113.0', $rows[0]['key_display']);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['limit' => 10, 'period' => 60, 'count' => 11, 'retryAfter' => 42], $meta);
    }

    #[Test]
    public function nonIpKeysAreStoredAsHashOnly(): void
    {
        $serverRequest = new ServerRequest('https://example.com/api', 'GET');

        $this->dispatch(new ThrottleExceeded('api-throttle', 'secret-api-key', 10, 60, 11, 42, $serverRequest, null));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame($this->keyHash('secret-api-key'), $rows[0]['key_hash']);
        self::assertSame('', $rows[0]['key_display']);
        self::assertStringNotContainsString('secret-api-key', json_encode($rows[0], JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function fail2BanMatchedEventStoresTheCounterMetaWithoutABanType(): void
    {
        $serverRequest = new ServerRequest('https://example.com/login', 'POST');

        $this->dispatch(new Fail2BanMatched('login-brute-force', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('fail2ban_matched', $rows[0]['event_type']);
        self::assertSame('login-brute-force', $rows[0]['rule']);
        self::assertSame($this->keyHash('203.0.113.10'), $rows[0]['key_hash']);
        self::assertSame('203.0.113.0', $rows[0]['key_display']);
        self::assertSame('', $rows[0]['ban_type']);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['threshold' => 5, 'period' => 300, 'count' => 3], $meta);
    }

    #[Test]
    public function fail2BanBlockedEventStoresTheBanType(): void
    {
        // Banned-key blocks are high-volume, so they are off by default. Keep
        // the shipped default types too: ExtensionConfiguration state leaks
        // into later tests in this class, which rely on the defaults.
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES . ',fail2ban_blocked']);

        $serverRequest = new ServerRequest('https://example.com/login', 'POST');

        $this->dispatch(new Fail2BanBlocked('login-brute-force', '203.0.113.10', $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('fail2ban_blocked', $rows[0]['event_type']);
        self::assertSame('login-brute-force', $rows[0]['rule']);
        self::assertSame($this->keyHash('203.0.113.10'), $rows[0]['key_hash']);
        self::assertSame('203.0.113.0', $rows[0]['key_display']);
        self::assertSame('fail2ban', $rows[0]['ban_type']);
    }

    #[Test]
    public function allow2BanBlockedEventStoresTheBanType(): void
    {
        // Banned-key blocks are high-volume, so they are off by default. Keep
        // the shipped default types too: ExtensionConfiguration state leaks
        // into later tests in this class, which rely on the defaults.
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES . ',allow2ban_blocked']);

        $serverRequest = new ServerRequest('https://example.com/form', 'POST');

        $this->dispatch(new Allow2BanBlocked('form-flood', '203.0.113.10', $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('allow2ban_blocked', $rows[0]['event_type']);
        self::assertSame('form-flood', $rows[0]['rule']);
        self::assertSame('allow2ban', $rows[0]['ban_type']);
    }

    #[Test]
    public function nestedDiagnosticHeadersMetaIsPersisted(): void
    {
        $serverRequest = new ServerRequest('https://example.com/probe', 'GET');
        $eventLogger = new EventLogger(
            $this->getConnectionPool(),
            new EventLogSettings($this->get(ExtensionConfiguration::class)),
            new KeyHasher(),
        );

        $eventLogger->log(FirewallEventType::BlocklistMatched, $serverRequest, rule: 'crs', meta: [
            'diagnosticHeaders' => ['X-Phirewall-Owasp-Rule' => '942100'],
        ]);

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['diagnosticHeaders' => ['X-Phirewall-Owasp-Rule' => '942100']], $meta);
    }

    #[Test]
    public function firewallErrorEventStoresTheExceptionSummary(): void
    {
        $serverRequest = new ServerRequest('https://example.com/', 'GET');

        $this->dispatch(new FirewallError(new \RuntimeException('Redis connection refused'), $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('firewall_error', $rows[0]['event_type']);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertSame(\RuntimeException::class, $meta['exceptionClass']);
        self::assertSame('Redis connection refused', $meta['exceptionMessage']);
    }

    #[Test]
    public function firewallErrorEventScrubsCredentialsFromTheMessage(): void
    {
        $serverRequest = new ServerRequest('https://example.com/', 'GET');

        $this->dispatch(new FirewallError(new \RuntimeException('Connection to redis://firewall:hunter2@redis:6379 refused'), $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertSame('Connection to redis://***@redis:6379 refused', $meta['exceptionMessage']);
        self::assertStringNotContainsString('hunter2', $rows[0]['meta']);
    }

    #[Test]
    public function oversizedMetaIsReplacedWithATruncationMarker(): void
    {
        $serverRequest = new ServerRequest('https://example.com/probe', 'GET');
        $eventLogger = new EventLogger(
            $this->getConnectionPool(),
            new EventLogSettings($this->get(ExtensionConfiguration::class)),
            new KeyHasher(),
        );

        $eventLogger->log(FirewallEventType::BlocklistMatched, $serverRequest, rule: 'oversized', meta: [
            'blob' => str_repeat('a', 70000),
        ]);

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertIsString($meta['_truncated']);
        self::assertStringContainsString('exceeded the 60000 byte limit', $meta['_truncated']);
        self::assertStringNotContainsString('aaaa', $rows[0]['meta']);
    }

    #[Test]
    public function credentialLikeParameterNamesAreMaskedAndLongNamesTruncated(): void
    {
        $longName = str_repeat('n', 80);
        $serverRequest = (new ServerRequest('https://example.com/login', 'POST'))
            ->withParsedBody([
                'x_apikey' => 'value-123',
                'authorization' => 'Bearer abc',
                $longName => 'value',
            ]);

        $this->dispatch(new Fail2BanMatched('login-brute-force', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertIsArray($meta['post']);
        self::assertSame('***', $meta['post']['x_apikey']);
        self::assertSame('***', $meta['post']['authorization']);
        self::assertArrayHasKey(str_repeat('n', 64), $meta['post']);
        self::assertArrayNotHasKey($longName, $meta['post']);
    }

    #[Test]
    public function safelistEventsAreNotLoggedByDefault(): void
    {
        $this->dispatch(new SafelistMatched('office-ips', new ServerRequest('https://example.com/', 'GET'), MatchResult::matched('custom')));

        self::assertSame([], $this->fetchAllEventRows());
    }

    #[Test]
    public function disabledLoggingWritesNothing(): void
    {
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '0']);

        $this->dispatch(new BlocklistMatched('scanner-paths', new ServerRequest('https://example.com/', 'GET'), MatchResult::matched('custom')));

        self::assertSame([], $this->fetchAllEventRows());
    }

    #[Test]
    public function pruneCommandIsRegisteredAsSchedulableConsoleCommand(): void
    {
        $commandRegistry = $this->get(CommandRegistry::class);

        self::assertTrue($commandRegistry->has('firewall:eventlog:prune'));
        $schedulableCommandNames = array_keys(iterator_to_array($commandRegistry->getSchedulableCommands()));
        self::assertContains('firewall:eventlog:prune', $schedulableCommandNames);
    }

    #[Test]
    public function pruneCommandDeletesOnlyEntriesOlderThanTheRetention(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(EventLogger::TABLE_NAME);
        $connection->insert(EventLogger::TABLE_NAME, ['event_type' => 'blocklist_matched', 'created_at' => time() - 10 * 86400]);
        $connection->insert(EventLogger::TABLE_NAME, ['event_type' => 'blocklist_matched', 'created_at' => time() - 3600]);

        $commandTester = new CommandTester($this->get(PruneEventLogCommand::class));
        $exitCode = $commandTester->execute(['--days' => '7']);

        self::assertSame(0, $exitCode);
        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertGreaterThan(time() - 7 * 86400, $rows[0]['created_at']);
    }

    private function dispatch(object $event): void
    {
        $this->get(EventDispatcherInterface::class)->dispatch($event);
    }

    private function keyHash(string $key): string
    {
        return (new KeyHasher())->hash($key);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function fetchAllEventRows(): array
    {
        return $this->getConnectionPool()
            ->getConnectionForTable(EventLogger::TABLE_NAME)
            ->select(['*'], EventLogger::TABLE_NAME)
            ->fetchAllAssociative();
    }
}
