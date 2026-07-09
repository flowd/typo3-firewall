<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\Form\FormFloodSettings;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\EventDispatcher\EventDispatcher;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[Autoconfigure(autowire: true)]
class ConfigFactory
{
    public function __construct(
        private readonly EventDispatcher $eventDispatcher,
        private readonly FormFloodSettings $formFloodSettings,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function fromConfigurationFile(): Config
    {
        return $this->fromFile(self::getConfigurationPath());
    }

    public function fromFile(string $configPath): Config
    {
        if (is_file($configPath)) {
            try {
                $configClosure = require $configPath;
                $config = null;

                if ($configClosure instanceof \Closure) {
                    $config = $configClosure($this->eventDispatcher);
                }

                if ($config instanceof Config) {
                    // The extension defaults form the base layer; the configuration
                    // file is merged on top and wins on every name clash.
                    return $this->warnAboutNonPersistentStore($this->createBaseConfig($config->cache)->with($config));
                }

                $this->logger?->warning('Invalid phirewall.php configuration file', ['path' => $configPath]);
            } catch (\Throwable $throwable) {
                $this->logger?->error($this->describeConfigurationError($throwable), [
                    'path' => $configPath,
                    'exception' => $throwable,
                ]);
            }
        }

        return $this->getDefaultConfig();
    }

    /**
     * A targeted hint for the common mistake of handing the mysqli based
     * TYPO3 connection to the PDO based store.
     */
    private function describeConfigurationError(\Throwable $throwable): string
    {
        if ($throwable instanceof \TypeError
            && str_contains($throwable->getMessage(), 'PDO')
            && str_contains($throwable->getMessage(), 'mysqli')
        ) {
            return 'Loading phirewall.php failed: the TYPO3 database connection uses the mysqli driver, '
                . 'but PdoCache needs a PDO driver such as pdo_mysql. Using the fallback configuration.';
        }

        return 'Loading phirewall.php failed, using the fallback configuration: ' . $throwable->getMessage();
    }

    /**
     * Throttle and ban counters need a store that persists between requests.
     * With InMemoryCache every HTTP request starts at zero, so such rules
     * silently never trigger; make that failure loud.
     */
    private function warnAboutNonPersistentStore(Config $config): Config
    {
        if ($this->isCliRequest() || !$config->cache instanceof InMemoryCache) {
            return $config;
        }

        if ($config->throttles->rules() === [] && $config->fail2ban->rules() === [] && $config->allow2ban->rules() === []) {
            return $config;
        }

        $this->logger?->warning(
            'Throttle, fail2ban, or allow2ban rules are registered on the InMemoryCache store. '
            . 'Counters do not persist between requests under PHP-FPM, so these rules never trigger. '
            . 'Use ApcuCache or RedisCache instead, see the Storage chapter of the manual.'
        );

        return $config;
    }

    protected function isCliRequest(): bool
    {
        return PHP_SAPI === 'cli';
    }

    private function getDefaultConfig(): Config
    {
        return $this->warnAboutNonPersistentStore($this->createBaseConfig(new InMemoryCache()));
    }

    /**
     * The defaults every installation gets: the TYPO3 client IP resolver and
     * the blocklist fed from the backend managed patterns. The configuration
     * file is layered on top, so it can override both by name.
     */
    private function createBaseConfig(CacheInterface $cache): Config
    {
        $config = new Config($cache, $this->eventDispatcher);

        // getIndpEnv() applies TYPO3's reverseProxyIP settings, so rules key on the real client IP.
        $config->setIpResolver(static function (): ?string {
            $remoteAddress = GeneralUtility::getIndpEnv('REMOTE_ADDR');
            return is_string($remoteAddress) && $remoteAddress !== '' ? $remoteAddress : null;
        });

        $patternPath = self::getPatternsFilePath();
        $fileArrayPatternBackend = new FileArrayPatternBackend($patternPath, new FileArrayWriter($patternPath, $this->logger), $this->logger);
        $config->blocklists->addPatternBackend('typo3-managed-patterns', $fileArrayPatternBackend)->fromBackend('typo3-blocklist', 'typo3-managed-patterns');

        $this->addFormFloodRule($config);

        return $config;
    }

    /**
     * The default "form-flood" allow2ban rule, fed by the FloodProtectionFinisher
     * and enabled through the extension configuration. A rule of the same name
     * in phirewall.php replaces it via the configuration overlay.
     */
    private function addFormFloodRule(Config $config): void
    {
        if (!$this->formFloodSettings->isEnabled()) {
            return;
        }

        $config->allow2ban->add(
            FormFloodSettings::DEFAULT_RULE_IDENTIFIER,
            threshold: $this->formFloodSettings->getThreshold(),
            period: $this->formFloodSettings->getPeriod(),
            banSeconds: $this->formFloodSettings->getBanSeconds(),
            // Fed by recorded hits only; the rule never matches a request on its own.
            filter: static fn(): bool => false,
        );
    }

    public static function getBaseConfigPath(): string
    {
        if (Environment::getProjectPath() !== Environment::getPublicPath()) {
            return Environment::getConfigPath();
        }

        return Environment::getLegacyConfigPath();
    }

    public static function getConfigurationPath(): string
    {
        return self::getBaseConfigPath() . '/system/phirewall.php';
    }

    public static function getPatternsFilePath(): string
    {
        return self::getBaseConfigPath() . '/system/phirewall.patterns.json';
    }
}
