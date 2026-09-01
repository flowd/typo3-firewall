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
use Flowd\Phirewall\Events\TrackHit;
use Flowd\Typo3Firewall\Command\PruneEventLogCommand;
use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Flowd\Typo3Firewall\EventLog\FirewallEventType;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
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
    private const string DEFAULT_EVENT_LOG_TYPES = 'blocklist_matched,throttle_exceeded,fail2ban_matched,fail2ban_banned,allow2ban_banned,track_threshold_reached,firewall_error';

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
    public function postParametersAreNotStoredInTheMeta(): void
    {
        $serverRequest = (new ServerRequest('https://example.com/login', 'POST'))
            ->withParsedBody([
                'username' => 'administrator',
                'pass' => 'hunter2',
            ]);

        $this->dispatch(new Fail2BanMatched('login-brute-force', '203.0.113.10', 5, 300, 3, $serverRequest, MatchResult::matched('custom')));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertArrayNotHasKey('post', $meta);
        self::assertStringNotContainsString('hunter2', $rows[0]['meta']);
        self::assertStringNotContainsString('administrator', $rows[0]['meta']);
    }

    #[Test]
    public function matchResultMetadataIsPersistedInTheMeta(): void
    {
        $serverRequest = (new ServerRequest('https://example.com/', 'GET'))
            ->withAddedHeader('User-Agent', 'curl /etc/passwd');

        $this->dispatch(new BlocklistMatched('owasp', $serverRequest, MatchResult::matched('owasp', [
            'owasp_rule_id' => 930121,
            'msg' => 'OS File Access Attempt in REQUEST_HEADERS',
            'owasp_matched_variable' => 'REQUEST_HEADERS:User-Agent',
            'owasp_matched_value' => 'curl /etc/passwd',
            'owasp_fail_closed' => false,
            'diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => '930121'],
        ])));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($meta);
        self::assertSame(930121, $meta['owasp_rule_id']);
        self::assertSame('OS File Access Attempt in REQUEST_HEADERS', $meta['msg']);
        self::assertSame('REQUEST_HEADERS:User-Agent', $meta['owasp_matched_variable']);
        self::assertSame('curl /etc/passwd', $meta['owasp_matched_value']);
        self::assertSame(['X-Phirewall-Owasp-Rule' => '930121'], $meta['diagnosticHeaders']);
        self::assertArrayNotHasKey('diagnostic_headers', $meta, 'The raw header fragment is folded into diagnosticHeaders');
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
    public function trackHitBelowTheThresholdIsLoggedAsTrackMatched(): void
    {
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES . ',track_matched']);

        try {
            $serverRequest = new ServerRequest('https://example.com/api', 'GET');
            $this->dispatch(new TrackHit('observed-endpoint', '203.0.113.10', 60, 3, $serverRequest, MatchResult::matched('custom'), 10));
            $this->dispatch(new TrackHit('unlimited-track', '203.0.113.10', 60, 500, $serverRequest, MatchResult::matched('custom')));

            $rows = $this->fetchAllEventRows();
            self::assertCount(2, $rows);
            self::assertSame('track_matched', $rows[0]['event_type']);
            self::assertSame('observed-endpoint', $rows[0]['rule']);
            self::assertIsString($rows[0]['meta']);
            $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
            self::assertSame(['period' => 60, 'count' => 3, 'limit' => 10], $meta);
            self::assertSame('track_matched', $rows[1]['event_type'], 'A track without a limit never reaches a threshold');
        } finally {
            $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES]);
        }
    }

    #[Test]
    public function trackHitReachingTheThresholdIsLoggedAsTrackThresholdReached(): void
    {
        $serverRequest = new ServerRequest('https://example.com/api', 'GET');

        $this->dispatch(new TrackHit('observed-endpoint', '203.0.113.10', 60, 10, $serverRequest, MatchResult::matched('custom'), 10));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows, 'track_threshold_reached is part of the default types');
        self::assertSame('track_threshold_reached', $rows[0]['event_type']);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['period' => 60, 'count' => 10, 'limit' => 10], $meta);
    }

    #[Test]
    public function subThresholdTrackHitsAreNotLoggedByDefault(): void
    {
        $serverRequest = new ServerRequest('https://example.com/api', 'GET');

        $this->dispatch(new TrackHit('observed-endpoint', '203.0.113.10', 60, 3, $serverRequest, MatchResult::matched('custom'), 10));

        self::assertSame([], $this->fetchAllEventRows());
    }

    #[Test]
    #[IgnoreDeprecations]
    public function deprecatedTrackHitTypeEnablesBothTrackTypes(): void
    {
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => 'track_hit']);

        try {
            $serverRequest = new ServerRequest('https://example.com/api', 'GET');
            $this->dispatch(new TrackHit('observed-endpoint', '203.0.113.10', 60, 3, $serverRequest, MatchResult::matched('custom'), 10));
            $this->dispatch(new TrackHit('observed-endpoint', '203.0.113.10', 60, 10, $serverRequest, MatchResult::matched('custom'), 10));

            $rows = $this->fetchAllEventRows();
            self::assertCount(2, $rows, 'The deprecated value keeps covering every track hit');
            self::assertSame('track_matched', $rows[0]['event_type']);
            self::assertSame('track_threshold_reached', $rows[1]['event_type']);
        } finally {
            $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '1', 'eventLogTypes' => self::DEFAULT_EVENT_LOG_TYPES]);
        }
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
