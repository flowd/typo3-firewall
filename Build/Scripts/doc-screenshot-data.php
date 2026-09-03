#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Seeds representative demo data for the documentation screenshots into a
 * TYPO3 installation and prints capture instructions. Run it from the
 * project root of the installation:
 *
 *   php packages/firewall/Build/Scripts/doc-screenshot-data.php [--truncate] [--yes]
 *
 * --truncate empties tx_firewall_event first, --yes skips the confirmation.
 * Re-running without --truncate adds duplicate events.
 */

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\KeyHasher;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Pattern\PatternStorageSettings;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Bootstrap;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;

$autoloadFile = getcwd() . '/vendor/autoload.php';
if (!is_file($autoloadFile)) {
    fwrite(STDERR, "Run this script from the project root of a Composer-based TYPO3 installation (vendor/autoload.php not found).\n");
    exit(1);
}

$classLoader = require $autoloadFile;
SystemEnvironmentBuilder::run(0, SystemEnvironmentBuilder::REQUESTTYPE_CLI);
$container = Bootstrap::init($classLoader);

$truncate = in_array('--truncate', $argv, true);
$confirmed = in_array('--yes', $argv, true);

if (!$confirmed) {
    fwrite(STDOUT, "This inserts firewall demo data (events, patterns, bans) into this installation.\nContinue? [y/N] ");
    $answer = trim((string)fgets(STDIN));
    if (!in_array(strtolower($answer), ['y', 'yes'], true)) {
        fwrite(STDOUT, "Aborted.\n");
        exit(0);
    }
}

$connection = $container->get(ConnectionPool::class)->getConnectionForTable(EventLogger::TABLE_NAME);
if ($truncate) {
    $connection->truncate(EventLogger::TABLE_NAME);
    fwrite(STDOUT, "Truncated tx_firewall_event.\n");
}

/** @var Config $config */
$config = $container->get(Config::class);
$keyHasher = new KeyHasher();
$now = time();

// Rule names from the actual configuration, so bans and blocked-key icons
// resolve; the event log itself accepts any rule string.
$fail2banRules = array_keys($config->fail2ban->rules());
$allow2banRules = array_keys($config->allow2ban->rules());
$loginRule = $fail2banRules[0] ?? 'login-protection';

$insertEvent = static function (array $row) use ($connection, $now): void {
    $connection->insert(EventLogger::TABLE_NAME, array_merge([
        'event_type' => 'blocklist_matched',
        'rule' => '',
        'ban_type' => '',
        'key_hash' => '',
        'key_display' => '',
        'request_host' => 'www.example.org',
        'request_method' => 'GET',
        'user_agent' => '',
        'meta' => '{}',
        'created_at' => $now,
    ], $row));
};

// A banned client with collapsed rows: full display so the lock icon and
// the ban resolution are visible.
foreach ([0, 240, 480, 900, 1500] as $index => $secondsAgo) {
    $insertEvent([
        'event_type' => $index === 0 ? 'fail2ban_banned' : 'fail2ban_matched',
        'rule' => $loginRule,
        'ban_type' => $index === 0 ? 'fail2ban' : '',
        'key_hash' => $keyHasher->hash('203.0.113.10'),
        'key_display' => '203.0.113.10',
        'request_path' => '/login',
        'request_method' => 'POST',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'meta' => $index === 0 ? '{"threshold":5,"period":300,"banSeconds":3600,"count":5}' : '{"threshold":5,"period":300,"count":' . (4 - $index) . '}',
        'created_at' => $now - $secondsAgo,
    ]);
}

// A client that is not banned yet: readable address with block action.
$insertEvent([
    'event_type' => 'fail2ban_matched',
    'rule' => $loginRule,
    'key_hash' => $keyHasher->hash('203.0.113.23'),
    'key_display' => '203.0.113.23',
    'request_path' => '/login',
    'request_method' => 'POST',
    'user_agent' => 'python-requests/2.32',
    'meta' => '{"threshold":5,"period":300,"count":2}',
    'created_at' => $now - 660,
]);

// An anonymized throttle key.
$insertEvent([
    'event_type' => 'throttle_exceeded',
    'rule' => 'search-throttle',
    'key_hash' => $keyHasher->hash('192.0.2.66'),
    'key_display' => '192.0.2.0',
    'request_path' => '/search?q=laminate+flooring',
    'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'meta' => '{"limit":20,"period":60,"count":21,"retryAfter":39}',
    'created_at' => $now - 1080,
]);

// An OWASP CRS match with rich metadata and captured request headers.
$insertEvent([
    'rule' => 'preset.owasp-crs.blocklist',
    'request_path' => '/index.php?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20be_users--',
    'user_agent' => 'sqlmap/1.8.5#stable (https://sqlmap.org)',
    'meta' => json_encode([
        'owasp_anomaly_score' => 10,
        'owasp_anomaly_threshold' => 5,
        'owasp_rule_id' => 942100,
        'msg' => 'SQL Injection Attack Detected via libinjection',
        'owasp_matched_variable' => 'ARGS:id',
        'owasp_matched_value' => "1' UNION SELECT username,password FROM be_users--",
        'diagnosticHeaders' => ['X-Phirewall-Owasp-Rule' => '942100', 'X-Phirewall-Owasp-Score' => '10/5'],
        'requestHeaders' => [
            'Host' => 'www.example.org',
            'User-Agent' => 'sqlmap/1.8.5#stable (https://sqlmap.org)',
            'Accept' => '*/*',
            'Accept-Encoding' => 'gzip, deflate',
            'Cookie' => '[redacted]',
        ],
    ], JSON_THROW_ON_ERROR),
    'created_at' => $now - 300,
]);

// A hash-only key from a header based throttle.
$insertEvent([
    'event_type' => 'throttle_exceeded',
    'rule' => 'api-throttle',
    'key_hash' => $keyHasher->hash('api-client-token'),
    'request_host' => 'api.example.org',
    'request_path' => '/api/search',
    'user_agent' => 'ExampleApp/3.2 (+https://www.example.org)',
    'meta' => '{"limit":60,"period":60,"count":74,"retryAfter":12}',
    'created_at' => $now - 2400,
]);

// Spread across the last day so the statistics chart shows a curve.
foreach (range(1, 23) as $hoursAgo) {
    $insertEvent([
        'rule' => 'preset.bad-ips.blocklist',
        'request_path' => '/.env',
        'user_agent' => 'Mozilla/5.0 zgrab/0.x',
        'created_at' => $now - $hoursAgo * 3600 + ($hoursAgo % 5) * 120,
    ]);
}

fwrite(STDOUT, "Inserted 30 demo events (rule names: {$loginRule}, search-throttle, api-throttle, presets).\n");

// Managed block patterns for the patterns view.
$patternStorageSettings = new PatternStorageSettings(GeneralUtility::makeInstance(ExtensionConfiguration::class));
$patternBackend = FileArrayPatternBackend::forFile($patternStorageSettings->getPatternsFilePath());
$patternBackend->append(new PatternEntry(PatternKind::IP, '203.0.113.99'));
$patternBackend->append(new PatternEntry(PatternKind::CIDR, '198.51.100.0/24', expiresAt: $now + 2 * 86400));
$patternBackend->append(new PatternEntry(PatternKind::PATH_PREFIX, '/.git/'));
$patternBackend->append(new PatternEntry(PatternKind::HEADER_REGEX, '#(sqlmap|nikto)#i', target: 'User-Agent'));
fwrite(STDOUT, "Added 4 block patterns.\n");

// Active bans, resolvable only for configured rules and a persistent store.
if ($config->cache instanceof InMemoryCache) {
    fwrite(STDOUT, "NOTE: the configured store is the InMemoryCache, bans cannot be seeded. Configure a persistent store to fill the Blocked keys view.\n");
} else {
    if ($fail2banRules !== []) {
        $config->banManager()->ban($fail2banRules[0], '203.0.113.10', 3540, BanType::Fail2Ban);
        fwrite(STDOUT, "Banned 203.0.113.10 for fail2ban rule '{$fail2banRules[0]}'.\n");
    } else {
        fwrite(STDOUT, "NOTE: no fail2ban rule configured, skipping the fail2ban demo ban.\n");
    }

    if ($allow2banRules !== []) {
        $config->banManager()->ban($allow2banRules[0], '198.51.100.7', 7140, BanType::Allow2Ban);
        fwrite(STDOUT, "Banned 198.51.100.7 for allow2ban rule '{$allow2banRules[0]}'.\n");
    } else {
        fwrite(STDOUT, "NOTE: no allow2ban rule configured, skipping the allow2ban demo ban.\n");
    }
}

fwrite(STDOUT, <<<INSTRUCTIONS

Capture instructions
====================
1. Set the extension setting eventLogFullIpRules to "{$loginRule}"
   (Admin Tools > Settings > Extension Configuration > firewall) so the
   events view shows the warning icon and the block action.
2. Log into the backend with a browser window about 1600px wide, light
   color scheme, and open System > Firewall.
3. Capture the module content area (without the TYPO3 module menu and top
   bar) for each view and save as:
   - Patterns      -> Documentation/Images/backend-module-patterns.png
   - Blocked keys  -> Documentation/Images/backend-module-bans.png
   - Event log     -> Documentation/Images/backend-module-events.png
   - Statistics    -> Documentation/Images/backend-module-statistics.png
4. Afterwards remove the demo data: re-run with --truncate to reset the
   event log, delete the four patterns in the Patterns view, lift the two
   bans in the Blocked keys view, and clear eventLogFullIpRules.

INSTRUCTIONS);
