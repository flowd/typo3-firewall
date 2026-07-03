<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\EventLog;

use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Typo3Firewall\Command\PruneEventLogCommand;
use Flowd\Typo3Firewall\EventLog\EventLogger;
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
    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    #[Test]
    public function blocklistMatchedEventIsLogged(): void
    {
        $serverRequest = (new ServerRequest('https://example.com/wp-admin/setup.php', 'GET'))
            ->withAddedHeader('User-Agent', 'sqlmap/1.0');

        $this->dispatch(new BlocklistMatched('scanner-paths', $serverRequest));

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
    public function throttleExceededEventStoresHashAndAnonymizedIpAndMeta(): void
    {
        $serverRequest = new ServerRequest('https://example.com/search', 'GET');

        $this->dispatch(new ThrottleExceeded('search-throttle', '203.0.113.10', 10, 60, 11, 42, $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame('throttle_exceeded', $rows[0]['event_type']);
        self::assertSame(hash('sha256', '203.0.113.10'), $rows[0]['key_hash']);
        self::assertSame('203.0.113.0', $rows[0]['key_display']);
        self::assertIsString($rows[0]['meta']);
        $meta = json_decode($rows[0]['meta'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['limit' => 10, 'period' => 60, 'count' => 11, 'retryAfter' => 42], $meta);
    }

    #[Test]
    public function nonIpKeysAreStoredAsHashOnly(): void
    {
        $serverRequest = new ServerRequest('https://example.com/api', 'GET');

        $this->dispatch(new ThrottleExceeded('api-throttle', 'secret-api-key', 10, 60, 11, 42, $serverRequest));

        $rows = $this->fetchAllEventRows();
        self::assertCount(1, $rows);
        self::assertSame(hash('sha256', 'secret-api-key'), $rows[0]['key_hash']);
        self::assertSame('', $rows[0]['key_display']);
        self::assertStringNotContainsString('secret-api-key', json_encode($rows[0], JSON_THROW_ON_ERROR));
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
    public function safelistEventsAreNotLoggedByDefault(): void
    {
        $this->dispatch(new SafelistMatched('office-ips', new ServerRequest('https://example.com/', 'GET')));

        self::assertSame([], $this->fetchAllEventRows());
    }

    #[Test]
    public function disabledLoggingWritesNothing(): void
    {
        $this->get(ExtensionConfiguration::class)->set('firewall', ['eventLogEnabled' => '0']);

        $this->dispatch(new BlocklistMatched('scanner-paths', new ServerRequest('https://example.com/', 'GET')));

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
