<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use TYPO3\CMS\Core\Core\Environment;

#[Autoconfigure(autowire: true)]
class ConfigFactory implements ConfigFactoryInterface
{
    public function __construct(
        protected readonly EventDispatcherInterface $eventDispatcher,
        protected readonly ExtensionConfiguration $extensionConfiguration,
        protected readonly ?LoggerInterface $logger = null,
    ) {}

    public function fromConfigurationFile(): Config
    {
        $configPath = $this->getConfigurationPath();

        if (is_file($configPath)) {
            $configClosure = require $configPath;
            $config = null;

            if ($configClosure instanceof \Closure) {
                $config = $configClosure($this->eventDispatcher);
            }

            if ($config instanceof Config) {
                return $this->applyActiveManagedRules($config);
            }

            $this->logger?->warning('Invalid phirewall.php configuration file', ['path' => $configPath]);
        }

        return $this->getDefaultConfig();
    }

    public static function getBaseConfigPath(): string
    {
        if (Environment::getProjectPath() !== Environment::getPublicPath()) {
            return Environment::getConfigPath();
        }

        return Environment::getLegacyConfigPath();
    }

    public function getConfigurationPath(): string
    {
        return static::getBaseConfigPath() . '/system/phirewall.php';
    }

    public function getPatternsFilePath(): string
    {
        return static::getBaseConfigPath() . '/system/phirewall.patterns.json';
    }

    private function getDefaultConfig(): Config
    {
        return $this->applyActiveManagedRules(new Config(new InMemoryCache(), $this->eventDispatcher));
    }

    private function addTypo3ManagedPatternsBlocklist(Config $config): Config
    {
        $patternPath = $this->getPatternsFilePath();
        $fileArrayPatternBackend = new FileArrayPatternBackend($patternPath, new FileArrayWriter($patternPath, $this->logger), $this->logger);

        $config->blocklists
            ->addPatternBackend('typo3-managed-patterns', $fileArrayPatternBackend)
            ->fromBackend('typo3-blocklist', 'typo3-managed-patterns');
        return $config;
    }

    /**
     * Registers a default "form-flood" fail2ban rule when enabled via extension
     * configuration: $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['firewall']['form']['flooding'].
     *
     * The rule is fed by the FloodProtectionFinisher (via
     * RequestContext::recordFailure()). A "form-flood" rule defined in
     * phirewall.php takes precedence and is left untouched.
     */
    private function addFormFloodRuleIfEnabled(Config $config): Config
    {
        if (!$this->extensionConfiguration->formFloodingProtection->enabled) {
            return $config;
        }

        if (isset($config->fail2ban->rules()['form-flood'])) {
            // rule already present => default has been overridden
            return $config;
        }

        $formFloodProtectionSettings = $this->extensionConfiguration->formFloodingProtection;
        $config->fail2ban->add(
            'form-flood',
            threshold: $formFloodProtectionSettings->threshold,
            period: $formFloodProtectionSettings->period,
            ban: $formFloodProtectionSettings->ban,
            filter: static fn(): bool => false,
            key: KeyExtractors::ip(),
        );

        return $config;
    }

    private function applyActiveManagedRules(Config $config): Config
    {
        return $this->addFormFloodRuleIfEnabled(
            $this->addTypo3ManagedPatternsBlocklist($config)
        );
    }
}
