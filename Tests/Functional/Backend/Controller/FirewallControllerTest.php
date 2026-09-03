<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Backend\Controller;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Backend\Controller\FirewallController;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Pattern\PatternStorageSettings;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Backend\Module\ModuleData;
use TYPO3\CMS\Backend\Module\ModuleProvider;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Core\Bootstrap;
use TYPO3\CMS\Extbase\Mvc\Controller\MvcPropertyMappingConfigurationService;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(FirewallController::class)]
final class FirewallControllerTest extends FunctionalTestCase
{
    private const string CONFIG_WITH_FAIL2BAN_RULE = <<<'PHP'
        <?php
        use Flowd\Phirewall\Config;
        use Flowd\Phirewall\Store\InMemoryCache;
        use Psr\EventDispatcher\EventDispatcherInterface;
        use Psr\Http\Message\ServerRequestInterface;

        return function (EventDispatcherInterface $eventDispatcher): Config {
            $config = new Config(new InMemoryCache(), $eventDispatcher);
            $config->fail2ban->add(
                name: '%s',
                threshold: 5,
                period: 60,
                ban: 3600,
                filter: fn(ServerRequestInterface $request): bool => $request->getUri()->getPath() === '/login'
            );
            return $config;
        };
        PHP;

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    private BackendUserAuthentication $backendUserAuthentication;

    protected function setUp(): void
    {
        parent::setUp();
        $this->importCSVDataSet(__DIR__ . '/../../Fixtures/be_users.csv');
        $this->backendUserAuthentication = $this->setUpBackendUser(1);
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences($this->backendUserAuthentication);

        // The instance directory survives between tests, only the database is reset.
        foreach ([$this->patternsFilePath(), ConfigFactory::getConfigurationPath()] as $filePath) {
            if (is_file($filePath)) {
                unlink($filePath);
            }
        }
    }

    #[Test]
    public function overviewActionRendersTheSeededPattern(): void
    {
        $this->createPatternBackend()->append(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/wp-admin'));

        $response = $this->dispatchModuleRequest('overview');

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('/wp-admin', (string)$response->getBody());
    }

    #[Test]
    public function createActionPersistsThePattern(): void
    {
        $response = $this->dispatchCreateRequest([
            'kind' => PatternKind::PATH_PREFIX->value,
            'value' => '/xmlrpc.php',
            'target' => '',
            'expiresAt' => '',
        ]);

        self::assertSame(303, $response->getStatusCode());
        $patterns = $this->createPatternBackend()->listRaw();
        self::assertCount(1, $patterns);
        self::assertSame('/xmlrpc.php', $patterns[0]['value']);
        self::assertSame(PatternKind::PATH_PREFIX->value, $patterns[0]['kind']);
    }

    #[Test]
    public function createActionWritesThePatternsFileToTheConfiguredDirectory(): void
    {
        $directory = Environment::getVarPath() . '/custom-patterns';
        $extensionConfiguration = $this->get(ExtensionConfiguration::class);
        $originalConfiguration = $extensionConfiguration->get('firewall');
        self::assertIsArray($originalConfiguration);
        $extensionConfiguration->set('firewall', array_merge($originalConfiguration, ['patternsDirectory' => $directory]));

        try {
            $response = $this->dispatchCreateRequest([
                'kind' => PatternKind::PATH_PREFIX->value,
                'value' => '/xmlrpc.php',
                'target' => '',
                'expiresAt' => '',
            ]);

            self::assertSame(303, $response->getStatusCode());
            self::assertFileExists($directory . '/phirewall.patterns.json');
        } finally {
            $extensionConfiguration->set('firewall', $originalConfiguration);
            GeneralUtility::rmdir($directory, true);
        }
    }

    #[Test]
    public function createActionRejectsAnUnknownKind(): void
    {
        $response = $this->dispatchCreateRequest([
            'kind' => 'not-a-kind',
            'value' => '/xmlrpc.php',
            'target' => '',
            'expiresAt' => '',
        ]);

        self::assertSame(303, $response->getStatusCode());
        self::assertSame([], $this->createPatternBackend()->listRaw());
    }

    #[Test]
    public function updateActionKeepsThePatternId(): void
    {
        $fileArrayPatternBackend = $this->createPatternBackend();
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/wp-admin'));

        $existingId = $fileArrayPatternBackend->listRaw()[0]['id'];

        $response = $this->dispatchModuleRequest('update', [
            'id' => $existingId,
            'patternEntryDto' => [
                'kind' => PatternKind::PATH_EXACT->value,
                'value' => '/wp-login.php',
                'target' => '',
                'expiresAt' => '',
            ],
            '__trustedProperties' => $this->generateTrustedPropertiesToken([
                'id',
                'patternEntryDto[kind]',
                'patternEntryDto[value]',
                'patternEntryDto[target]',
                'patternEntryDto[expiresAt]',
            ]),
        ], 'POST');

        self::assertSame(303, $response->getStatusCode());
        $patterns = $this->createPatternBackend()->listRaw();
        self::assertCount(1, $patterns);
        self::assertSame($existingId, $patterns[0]['id']);
        self::assertSame('/wp-login.php', $patterns[0]['value']);
        self::assertSame(PatternKind::PATH_EXACT->value, $patterns[0]['kind']);
    }

    #[Test]
    public function deleteActionRemovesThePattern(): void
    {
        $fileArrayPatternBackend = $this->createPatternBackend();
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/wp-admin'));

        $existingId = $fileArrayPatternBackend->listRaw()[0]['id'];

        $response = $this->dispatchModuleRequest('delete', ['id' => $existingId], 'POST');

        self::assertSame(303, $response->getStatusCode());
        self::assertSame([], $this->createPatternBackend()->listRaw());
    }

    #[Test]
    public function pruneActionRemovesOnlyExpiredPatterns(): void
    {
        $fileArrayPatternBackend = $this->createPatternBackend();
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/expired', expiresAt: time() - 60));
        $fileArrayPatternBackend->append(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/active', expiresAt: time() + 3600));

        $response = $this->dispatchModuleRequest('prune', [], 'POST');

        self::assertSame(303, $response->getStatusCode());
        $patterns = $this->createPatternBackend()->listRaw();
        self::assertCount(1, $patterns);
        self::assertSame('/active', $patterns[0]['value']);
    }

    #[Test]
    public function bansActionListsAnActiveBan(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        $config->banManager()->ban('login-protection', '203.0.113.10', 3600, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('bans');

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('203.0.113.10', (string)$response->getBody());
    }

    #[Test]
    public function statisticsActionRendersSeededEvents(): void
    {
        $this->getConnectionPool()->getConnectionForTable('tx_firewall_event')->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'scanner-paths',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'key_display' => '203.0.113.0/24',
            'request_path' => '/wp-admin',
            'request_method' => 'GET',
            'created_at' => time() - 60,
        ]);

        $response = $this->dispatchModuleRequest('statistics');

        $body = (string)$response->getBody();
        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('Attackers blocked today', $body);
        self::assertStringContainsString('scanner-paths', $body);
        self::assertStringContainsString('/wp-admin', $body);
        self::assertStringContainsString('<svg', $body);
        self::assertStringContainsString('#2a78d6', $body);
        self::assertStringContainsString('Recent blocked requests', $body);
        self::assertStringContainsString('GET /wp-admin', $body);
        self::assertStringContainsString('203.0.113.0/24', $body);
    }

    #[Test]
    public function moduleEntryDefaultsToThePatternView(): void
    {
        $body = (string)$this->dispatchModuleRequest(null)->getBody();

        self::assertStringContainsString('Active Patterns', $body);
    }

    #[Test]
    public function moduleEntryOpensTheLastVisitedView(): void
    {
        $this->dispatchModuleRequest('statistics');

        $body = (string)$this->dispatchModuleRequest(null)->getBody();

        self::assertStringContainsString('Attackers blocked today', $body);
    }

    #[Test]
    public function statisticsActionCollapsesRecentEventsPerKeyAndLinksToTheEventLog(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        for ($i = 0; $i < 5; ++$i) {
            $connection->insert('tx_firewall_event', [
                'event_type' => 'throttle_exceeded',
                'rule' => 'flood-rule',
                'key_hash' => $this->keyHash('203.0.113.10'),
                'key_display' => '203.0.113.0',
                'request_path' => '/flood',
                'request_method' => 'GET',
                'created_at' => $now - $i,
            ]);
        }

        $body = (string)$this->dispatchModuleRequest('statistics')->getBody();

        self::assertSame(3, substr_count($body, '203.0.113.0'));
        self::assertSame(1, substr_count($body, '+2 more'));
        self::assertStringContainsString($this->keyHash('203.0.113.10'), $body);
    }

    #[Test]
    public function bansActionWarnsAboutTheInMemoryStore(): void
    {
        $this->setUpConfigWithFail2BanRule();

        $response = $this->dispatchModuleRequest('bans');

        self::assertStringContainsString('InMemoryCache', (string)$response->getBody());
    }

    #[Test]
    public function bansActionShowsTheRemainingBanTime(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        // 150 seconds keep the label at "2 min" even when rendering takes a few seconds.
        $config->banManager()->ban('login-protection', '203.0.113.10', 150, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('bans');

        $body = (string)$response->getBody();
        self::assertStringContainsString('2 min', $body);
    }

    #[Test]
    public function bansActionFiltersByTheSearchTerm(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        $config->banManager()->ban('login-protection', '203.0.113.10', 3600, BanType::Fail2Ban);
        $config->banManager()->ban('login-protection', '198.51.100.7', 3600, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('bans', ['search' => '203.0'], 'POST');

        $body = (string)$response->getBody();
        self::assertStringContainsString('203.0.113.10', $body);
        self::assertStringNotContainsString('198.51.100.7', $body);
    }

    #[Test]
    public function bansActionSortsBansBySoonestExpiry(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        $config->banManager()->ban('login-protection', '203.0.113.10', 3600, BanType::Fail2Ban);
        $config->banManager()->ban('login-protection', '198.51.100.7', 60, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('bans');

        $body = (string)$response->getBody();
        $positionSoonest = strpos($body, '198.51.100.7');
        $positionLater = strpos($body, '203.0.113.10');
        self::assertNotFalse($positionSoonest);
        self::assertNotFalse($positionLater);
        self::assertLessThan($positionLater, $positionSoonest);
    }

    #[Test]
    public function bansActionBuildsSelectorSafeConfirmFormTargetsForDottedRuleNames(): void
    {
        $config = $this->setUpConfigWithFail2BanRule('preset.owasp-crs.fail2ban');
        $config->banManager()->ban('preset.owasp-crs.fail2ban', '203.0.113.10', 3600, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('bans');

        $body = (string)$response->getBody();
        self::assertStringContainsString('t3js-modal-trigger', $body);
        self::assertSame(1, preg_match_all('/data-target-form="(?<targets>[^"]*)"/', $body, $matches));
        foreach ($matches['targets'] as $target) {
            // The core modal locates the form via querySelector('form#...'), so a CSS
            // metacharacter in the id (e.g. the dot of a rule name like
            // "preset.owasp-crs.fail2ban") would leave the unban button dead.
            self::assertMatchesRegularExpression('/^[A-Za-z][A-Za-z0-9_-]*$/', $target);
            self::assertStringContainsString(sprintf('id="%s"', $target), $body);
        }
    }

    #[Test]
    public function eventsActionListsEventsWithFlattenedMeta(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $this->getConnectionPool()->getConnectionForTable('tx_firewall_event')->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'preset.owasp-crs.blocklist',
            'key_display' => '203.0.113.0',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'request_host' => 'example.com',
            'request_path' => '/probe',
            'request_method' => 'GET',
            'user_agent' => 'scanner/1.0',
            'meta' => '{"diagnosticHeaders":{"X-Phirewall-Owasp-Rule":"942100"}}',
            'created_at' => time(),
        ]);

        $response = $this->dispatchModuleRequest('events');
        $body = (string)$response->getBody();

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('preset.owasp-crs.blocklist', $body);
        self::assertStringContainsString('diagnosticHeaders.X-Phirewall-Owasp-Rule: 942100', $body);
        self::assertStringContainsString('scanner/1.0', $body);
    }

    #[Test]
    public function eventsActionFiltersByEventType(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'scanner-paths',
            'created_at' => time(),
        ]);
        $connection->insert('tx_firewall_event', [
            'event_type' => 'track_hit',
            'rule' => 'observed-endpoint',
            'created_at' => time(),
        ]);

        $body = (string)$this->dispatchModuleRequest('events', ['types' => ['track_hit']])->getBody();

        self::assertStringContainsString('observed-endpoint', $body);
        self::assertStringNotContainsString('scanner-paths', $body);
    }

    #[Test]
    public function eventsActionFiltersByMultipleEventTypes(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        foreach (['blocklist_matched' => 'scanner-paths', 'track_hit' => 'observed-endpoint', 'firewall_error' => 'store-error'] as $eventType => $rule) {
            $connection->insert('tx_firewall_event', [
                'event_type' => $eventType,
                'rule' => $rule,
                'created_at' => time(),
            ]);
        }

        $body = (string)$this->dispatchModuleRequest('events', ['types' => ['track_hit', 'firewall_error']])->getBody();

        self::assertStringContainsString('observed-endpoint', $body);
        self::assertStringContainsString('store-error', $body);
        self::assertStringNotContainsString('scanner-paths', $body);
    }

    #[Test]
    public function eventsActionCollapsesRepeatedKeyEventsToTheNewestThree(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        for ($i = 0; $i < 5; ++$i) {
            $connection->insert('tx_firewall_event', [
                'event_type' => 'throttle_exceeded',
                'rule' => 'flood-rule-' . $i,
                'key_hash' => $this->keyHash('203.0.113.10'),
                'key_display' => '203.0.113.0',
                'created_at' => $now - $i,
            ]);
        }

        $body = (string)$this->dispatchModuleRequest('events')->getBody();

        self::assertStringContainsString('flood-rule-0', $body);
        self::assertStringContainsString('flood-rule-1', $body);
        self::assertStringContainsString('flood-rule-2', $body);
        self::assertStringNotContainsString('flood-rule-3', $body);
        self::assertStringNotContainsString('flood-rule-4', $body);
        self::assertStringContainsString('+2 more', $body);
        self::assertStringContainsString($this->keyHash('203.0.113.10'), $body);
    }

    #[Test]
    public function eventsActionDoesNotCollapseEventsWithoutAKey(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        for ($i = 0; $i < 5; ++$i) {
            $connection->insert('tx_firewall_event', [
                'event_type' => 'blocklist_matched',
                'rule' => 'probe-rule-' . $i,
                'created_at' => $now - $i,
            ]);
        }

        $body = (string)$this->dispatchModuleRequest('events')->getBody();

        for ($i = 0; $i < 5; ++$i) {
            self::assertStringContainsString('probe-rule-' . $i, $body);
        }

        self::assertStringNotContainsString('+2 more', $body);
    }

    #[Test]
    public function eventsActionKeyFilterListsAllEventsForTheKey(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        for ($i = 0; $i < 5; ++$i) {
            $connection->insert('tx_firewall_event', [
                'event_type' => 'throttle_exceeded',
                'rule' => 'flood-rule-' . $i,
                'key_hash' => $this->keyHash('203.0.113.10'),
                'key_display' => '203.0.113.0',
                'created_at' => $now - $i,
            ]);
        }

        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'other-client-rule',
            'key_hash' => $this->keyHash('198.51.100.7'),
            'key_display' => '198.51.100.0',
            'created_at' => $now,
        ]);

        $body = (string)$this->dispatchModuleRequest('events', ['key' => $this->keyHash('203.0.113.10')])->getBody();

        for ($i = 0; $i < 5; ++$i) {
            self::assertStringContainsString('flood-rule-' . $i, $body);
        }

        self::assertStringNotContainsString('other-client-rule', $body);
        self::assertStringContainsString('Remove the key filter', $body);
    }

    #[Test]
    public function eventsActionFiltersByAClickedRule(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'key_display' => '203.0.113.0',
            'created_at' => time(),
        ]);
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'other-rule',
            'key_hash' => $this->keyHash('198.51.100.7'),
            'key_display' => '198.51.100.0',
            'created_at' => time(),
        ]);

        $body = (string)$this->dispatchModuleRequest('events', ['rule' => 'flood-rule'])->getBody();

        self::assertStringContainsString('flood-rule', $body);
        self::assertStringNotContainsString('other-rule', $body);
        self::assertStringContainsString('Remove the rule filter', $body);
    }

    #[Test]
    public function eventsActionFindsAnonymizedKeyEventsBySearchingTheFullIp(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('20.251.48.208'),
            'key_display' => '20.251.48.0',
            'created_at' => time(),
        ]);
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'other-client-rule',
            'key_hash' => $this->keyHash('198.51.100.7'),
            'key_display' => '198.51.100.0',
            'created_at' => time(),
        ]);

        $body = (string)$this->dispatchModuleRequest('events', ['search' => '20.251.48.208'], 'POST')->getBody();

        self::assertStringContainsString('flood-rule', $body);
        self::assertStringNotContainsString('other-client-rule', $body);
    }

    #[Test]
    public function eventsActionPaginatesOlderEventsOntoTheNextPage(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        $connection->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'oldest-entry',
            'created_at' => $now - 1000,
        ]);
        for ($i = 0; $i < 50; ++$i) {
            $connection->insert('tx_firewall_event', [
                'event_type' => 'blocklist_matched',
                'rule' => 'filler-' . $i,
                'created_at' => $now,
            ]);
        }

        $firstPage = (string)$this->dispatchModuleRequest('events')->getBody();
        self::assertStringNotContainsString('oldest-entry', $firstPage);
        self::assertStringContainsString('Page 1 of 2', $firstPage);

        $secondPage = (string)$this->dispatchModuleRequest('events', ['page' => '2'])->getBody();
        self::assertStringContainsString('oldest-entry', $secondPage);
        self::assertStringNotContainsString('filler-0', $secondPage);
    }

    #[Test]
    public function eventsActionKeyFilterCombinesWithSearchAndTypeFilters(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        $flooderHash = $this->keyHash('203.0.113.10');
        foreach ([
            ['event_type' => 'throttle_exceeded', 'rule' => 'flood-login', 'key_hash' => $flooderHash, 'request_path' => '/login'],
            ['event_type' => 'throttle_exceeded', 'rule' => 'flood-search', 'key_hash' => $flooderHash, 'request_path' => '/search'],
            ['event_type' => 'blocklist_matched', 'rule' => 'probe-login', 'key_hash' => $flooderHash, 'request_path' => '/login'],
            ['event_type' => 'throttle_exceeded', 'rule' => 'other-login', 'key_hash' => $this->keyHash('198.51.100.7'), 'request_path' => '/login'],
        ] as $eventRow) {
            $connection->insert('tx_firewall_event', array_merge([
                'key_display' => '203.0.113.0',
                'request_method' => 'GET',
                'created_at' => $now,
            ], $eventRow));
        }

        $body = (string)$this->dispatchModuleRequest('events', [
            'types' => ['throttle_exceeded'],
            'search' => 'login',
            'key' => $flooderHash,
        ])->getBody();

        self::assertStringContainsString('flood-login', $body);
        self::assertStringNotContainsString('flood-search', $body);
        self::assertStringNotContainsString('probe-login', $body);
        self::assertStringNotContainsString('other-login', $body);
        self::assertStringContainsString('Remove the key filter', $body);
    }

    #[Test]
    public function eventsActionRendersAHashOnlyKeyAsACroppedHash(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $keyHash = $this->keyHash('secret-api-key');
        $this->getConnectionPool()->getConnectionForTable('tx_firewall_event')->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'api-flood',
            'key_hash' => $keyHash,
            'key_display' => '',
            'request_path' => '/api',
            'request_method' => 'GET',
            'created_at' => time(),
        ]);

        $croppedHash = substr($keyHash, 0, 12) . '…';

        $timelineBody = (string)$this->dispatchModuleRequest('events')->getBody();
        self::assertStringContainsString($croppedHash, $timelineBody);
        self::assertStringContainsString($keyHash, $timelineBody);

        $keyFilterBody = (string)$this->dispatchModuleRequest('events', ['key' => $keyHash])->getBody();
        self::assertStringContainsString('api-flood', $keyFilterBody);
        self::assertStringContainsString($croppedHash, $keyFilterBody);
        self::assertStringContainsString('Remove the key filter', $keyFilterBody);
    }

    #[Test]
    public function eventsActionTrimsWhitespaceBeforeHashingTheSearchedIp(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('20.251.48.208'),
            'key_display' => '20.251.48.0',
            'created_at' => time(),
        ]);
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'other-client-rule',
            'key_hash' => $this->keyHash('198.51.100.7'),
            'key_display' => '198.51.100.0',
            'created_at' => time(),
        ]);

        $body = (string)$this->dispatchModuleRequest('events', ['search' => '  20.251.48.208  '], 'POST')->getBody();

        self::assertStringContainsString('flood-rule', $body);
        self::assertStringNotContainsString('other-client-rule', $body);
    }

    #[Test]
    public function eventsActionRestoresPersistedFiltersOnPlainNavigation(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', ['event_type' => 'track_hit', 'rule' => 'observed-endpoint', 'created_at' => time()]);
        $connection->insert('tx_firewall_event', ['event_type' => 'blocklist_matched', 'rule' => 'scanner-paths', 'created_at' => time()]);

        $filteredBody = (string)$this->dispatchModuleRequest('events', ['types' => ['track_hit'], 'operation' => 'filter'])->getBody();
        self::assertStringNotContainsString('scanner-paths', $filteredBody);

        $plainBody = (string)$this->dispatchModuleRequest('events')->getBody();
        self::assertStringContainsString('observed-endpoint', $plainBody);
        self::assertStringNotContainsString('scanner-paths', $plainBody);
    }

    #[Test]
    public function eventsActionResetFiltersClearsThePersistedState(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', ['event_type' => 'track_hit', 'rule' => 'observed-endpoint', 'created_at' => time()]);
        $connection->insert('tx_firewall_event', ['event_type' => 'blocklist_matched', 'rule' => 'scanner-paths', 'created_at' => time()]);

        $this->dispatchModuleRequest('events', ['types' => ['track_hit'], 'operation' => 'filter']);
        $resetBody = (string)$this->dispatchModuleRequest('events', ['operation' => 'reset-filters'])->getBody();
        self::assertStringContainsString('scanner-paths', $resetBody);

        $plainBody = (string)$this->dispatchModuleRequest('events')->getBody();
        self::assertStringContainsString('scanner-paths', $plainBody);
        self::assertStringContainsString('observed-endpoint', $plainBody);
    }

    #[Test]
    public function eventsActionKeyFilterIgnoresPersistedFilters(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'key_display' => '203.0.113.0',
            'created_at' => time(),
        ]);

        $this->dispatchModuleRequest('events', ['types' => ['track_hit'], 'operation' => 'filter']);
        $keyBody = (string)$this->dispatchModuleRequest('events', ['key' => $this->keyHash('203.0.113.10')])->getBody();

        self::assertStringContainsString('flood-rule', $keyBody);
        self::assertStringContainsString('Remove the key filter', $keyBody);
    }

    #[Test]
    public function statisticsActionPersistsTheSelectedRange(): void
    {
        $this->getConnectionPool()->getConnectionForTable('tx_firewall_event')->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'scanner-paths',
            'created_at' => time(),
        ]);

        $this->dispatchModuleRequest('statistics', ['range' => '7d']);
        $plainBody = (string)$this->dispatchModuleRequest('statistics')->getBody();

        self::assertStringContainsString('(7 days)', $plainBody);
    }

    #[Test]
    public function eventsActionRendersManyDetailLinesInsideADetailsElement(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $now = time();
        $connection->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'many-meta',
            'request_path' => '/.env',
            'request_method' => 'GET',
            'meta' => '{"alpha":"1","beta":"2","gamma":"3","delta":"4"}',
            'created_at' => $now,
        ]);
        $connection->insert('tx_firewall_event', [
            'event_type' => 'blocklist_matched',
            'rule' => 'few-meta',
            'request_path' => '/.git/config',
            'request_method' => 'GET',
            'meta' => '{"alpha":"1","beta":"2"}',
            'created_at' => $now - 1,
        ]);

        $body = (string)$this->dispatchModuleRequest('events')->getBody();

        self::assertStringContainsString('many-meta', $body);
        self::assertStringContainsString('few-meta', $body);
        self::assertStringContainsString('4 details', $body);
        self::assertStringContainsString('gamma: 3', $body);
        self::assertSame(1, substr_count($body, '<details>'));
    }

    #[Test]
    public function unbanActionRemovesTheBan(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        $config->banManager()->ban('login-protection', '203.0.113.10', 3600, BanType::Fail2Ban);

        $response = $this->dispatchModuleRequest('unban', [
            'rule' => 'login-protection',
            'key' => '203.0.113.10',
            'type' => BanType::Fail2Ban->value,
        ], 'POST');

        self::assertSame(303, $response->getStatusCode());
        self::assertFalse($config->banManager()->isBanned('login-protection', '203.0.113.10', BanType::Fail2Ban));
    }

    #[Test]
    public function eventsActionPersistsExcludedKeysAndTheRange(): void
    {
        $this->setUpConfigWithFail2BanRule();
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_firewall_event');
        $connection->insert('tx_firewall_event', [
            'event_type' => 'throttle_exceeded',
            'rule' => 'flood-rule',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'key_display' => '203.0.113.10',
            'created_at' => time(),
        ]);
        $connection->insert('tx_firewall_event', ['event_type' => 'blocklist_matched', 'rule' => 'old-rule', 'created_at' => time() - 10 * 86400]);

        $filteredBody = (string)$this->dispatchModuleRequest('events', [
            'excludeKeys' => [$this->keyHash('203.0.113.10')],
            'range' => 'all',
            'operation' => 'filter',
        ])->getBody();
        self::assertStringNotContainsString('flood-rule', $filteredBody);
        self::assertStringContainsString('old-rule', $filteredBody, 'The "all" range shows events older than the default range');

        $plainBody = (string)$this->dispatchModuleRequest('events')->getBody();
        self::assertStringNotContainsString('flood-rule', $plainBody);
        self::assertStringContainsString('old-rule', $plainBody);
        self::assertStringContainsString('Hidden keys', $plainBody);
    }

    #[Test]
    public function eventsActionShowsTheBlockedIconForABannedKey(): void
    {
        $config = $this->setUpConfigWithFail2BanRule();
        $config->banManager()->ban('login-protection', '203.0.113.10', 3600, BanType::Fail2Ban);
        $this->getConnectionPool()->getConnectionForTable('tx_firewall_event')->insert('tx_firewall_event', [
            'event_type' => 'fail2ban_banned',
            'rule' => 'login-protection',
            'key_hash' => $this->keyHash('203.0.113.10'),
            'key_display' => '203.0.113.10',
            'created_at' => time(),
        ]);

        $body = (string)$this->dispatchModuleRequest('events')->getBody();

        self::assertStringContainsString('Currently banned: login-protection (fail2ban)', $body);
    }

    #[Test]
    public function blockKeyActionCreatesAnIpPatternEntryForThePostedIp(): void
    {
        $response = $this->dispatchModuleRequest('blockKey', ['ip' => '203.0.113.10', 'key' => $this->keyHash('203.0.113.10')], 'POST');

        self::assertSame(303, $response->getStatusCode());
        $patterns = $this->createPatternBackend()->listRaw();
        self::assertCount(1, $patterns);
        self::assertSame(PatternKind::IP->value, $patterns[0]['kind']);
        self::assertSame('203.0.113.10', $patterns[0]['value']);
    }

    #[Test]
    public function blockKeyActionRejectsAnAnonymizedNetworkAddress(): void
    {
        $response = $this->dispatchModuleRequest('blockKey', ['ip' => '203.0.113.0', 'key' => $this->keyHash('203.0.113.10')], 'POST');

        self::assertSame(303, $response->getStatusCode());
        self::assertCount(0, $this->createPatternBackend()->listRaw());
    }

    #[Test]
    public function blockKeyActionRejectsANonIpValue(): void
    {
        $response = $this->dispatchModuleRequest('blockKey', ['ip' => 'not-an-ip', 'key' => $this->keyHash('not-an-ip')], 'POST');

        self::assertSame(303, $response->getStatusCode());
        self::assertCount(0, $this->createPatternBackend()->listRaw());
    }

    /**
     * @param array<string, string> $patternEntryDto
     */
    private function dispatchCreateRequest(array $patternEntryDto): ResponseInterface
    {
        return $this->dispatchModuleRequest('create', [
            'patternEntryDto' => $patternEntryDto,
            '__trustedProperties' => $this->generateTrustedPropertiesToken([
                'patternEntryDto[kind]',
                'patternEntryDto[value]',
                'patternEntryDto[target]',
                'patternEntryDto[expiresAt]',
            ]),
        ], 'POST');
    }

    /**
     * A null action dispatches the plain module entry point, like opening
     * the module from the module menu.
     *
     * @param array<string, mixed> $arguments
     */
    private function dispatchModuleRequest(?string $action, array $arguments = [], string $method = 'GET'): ResponseInterface
    {
        $module = $this->get(ModuleProvider::class)->getModule('system_firewall', $this->backendUserAuthentication);
        self::assertNotNull($module, 'The system_firewall module must be registered and accessible.');
        // Extbase backend modules read their arguments without a plugin namespace.
        $parameters = $action === null ? $arguments : array_merge(['action' => $action], $arguments);

        $routeOptions = [
            'module' => $module,
            'moduleName' => 'system_firewall',
            'packageName' => 'flowd/typo3-firewall',
            '_identifier' => 'system_firewall',
        ];
        if ($action !== null) {
            $routeOptions['action'] = $action;
        }

        $route = new Route('/module/system/firewall', $routeOptions);
        // Mirrors the backend module router: module data comes from the user's uc.
        $storedModuleData = $this->backendUserAuthentication->getModuleData('system_firewall');
        $serverRequest = (new ServerRequest('https://typo3-testing.local/typo3/module/system/firewall', $method))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE)
            ->withAttribute('module', $module)
            ->withAttribute('route', $route)
            ->withAttribute('moduleData', ModuleData::createFromModule($module, is_array($storedModuleData) ? $storedModuleData : []));

        if ($method === 'POST') {
            $serverRequest = $serverRequest->withParsedBody($parameters);
        } else {
            $serverRequest = $serverRequest->withQueryParams($parameters);
        }

        // TYPO3 v14 requires normalizedParams for backend module rendering and redirects.
        $serverRequest = $serverRequest->withAttribute(
            'normalizedParams',
            NormalizedParams::createFromRequest($serverRequest)
        );

        // TYPO3 v12 module rendering appends to the PageRenderer singleton; reset it between dispatches.
        GeneralUtility::makeInstance(PageRenderer::class)->setBodyContent('');

        $GLOBALS['TYPO3_REQUEST'] = $serverRequest;

        return $this->get(Bootstrap::class)->handleBackendRequest($serverRequest);
    }

    /**
     * @param list<string> $propertyNames
     */
    private function generateTrustedPropertiesToken(array $propertyNames): string
    {
        return $this->get(MvcPropertyMappingConfigurationService::class)
            ->generateTrustedPropertiesToken($propertyNames);
    }

    private function setUpConfigWithFail2BanRule(string $ruleName = 'login-protection'): Config
    {
        $configDirectory = dirname(ConfigFactory::getConfigurationPath());
        if (!is_dir($configDirectory)) {
            mkdir($configDirectory, 0o755, true);
        }

        file_put_contents(ConfigFactory::getConfigurationPath(), sprintf(self::CONFIG_WITH_FAIL2BAN_RULE, $ruleName));

        return $this->get(Config::class);
    }

    private function createPatternBackend(): FileArrayPatternBackend
    {
        $patternsFilePath = $this->patternsFilePath();

        return new FileArrayPatternBackend($patternsFilePath, new FileArrayWriter($patternsFilePath));
    }

    private function patternsFilePath(): string
    {
        return $this->get(PatternStorageSettings::class)->getPatternsFilePath();
    }

    private function keyHash(string $key): string
    {
        return (new KeyHasher())->hash($key);
    }
}
