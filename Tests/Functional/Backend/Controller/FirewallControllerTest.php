<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Backend\Controller;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Backend\Controller\FirewallController;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Backend\Module\ModuleProvider;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
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
                name: 'login-protection',
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
        foreach ([ConfigFactory::getPatternsFilePath(), ConfigFactory::getConfigurationPath()] as $filePath) {
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
            'key_hash' => hash('sha256', '203.0.113.10'),
            'request_path' => '/wp-admin',
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
     * @param array<string, mixed> $arguments
     */
    private function dispatchModuleRequest(string $action, array $arguments = [], string $method = 'GET'): ResponseInterface
    {
        $module = $this->get(ModuleProvider::class)->getModule('system_firewall', $this->backendUserAuthentication);
        self::assertNotNull($module, 'The system_firewall module must be registered and accessible.');
        // Extbase backend modules read their arguments without a plugin namespace.
        $parameters = array_merge(['action' => $action], $arguments);

        $route = new Route('/module/system/firewall', [
            'module' => $module,
            'moduleName' => 'system_firewall',
            'packageName' => 'flowd/typo3-firewall',
            '_identifier' => 'system_firewall',
            'action' => $action,
        ]);
        $serverRequest = (new ServerRequest('https://typo3-testing.local/typo3/module/system/firewall', $method))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE)
            ->withAttribute('module', $module)
            ->withAttribute('route', $route);

        if ($method === 'POST') {
            $serverRequest = $serverRequest->withParsedBody($parameters);
        } else {
            $serverRequest = $serverRequest->withQueryParams($parameters);
        }

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

    private function setUpConfigWithFail2BanRule(): Config
    {
        $configDirectory = dirname(ConfigFactory::getConfigurationPath());
        if (!is_dir($configDirectory)) {
            mkdir($configDirectory, 0o755, true);
        }

        file_put_contents(ConfigFactory::getConfigurationPath(), self::CONFIG_WITH_FAIL2BAN_RULE);

        return $this->get(Config::class);
    }

    private function createPatternBackend(): FileArrayPatternBackend
    {
        $patternsFilePath = ConfigFactory::getPatternsFilePath();

        return new FileArrayPatternBackend($patternsFilePath, new FileArrayWriter($patternsFilePath));
    }
}
