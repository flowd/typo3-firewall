<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit;

use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Flowd\Typo3Firewall\Tests\Unit\Fixtures\FixtureConfigFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\EventDispatcher\NoopEventDispatcher;

#[CoversClass(ConfigFactory::class)]
final class ConfigFactoryTest extends TestCase
{
    #[Test]
    public function getConfigurationPathReturnsPhpFilePath(): void
    {
        self::assertStringEndsWith('/system/phirewall.php', $this->getConfigFactory([])->getConfigurationPath());
    }

    #[Test]
    public function getPatternsFilePathReturnsJsonFilePath(): void
    {
        self::assertStringEndsWith('/system/phirewall.patterns.json', $this->getConfigFactory([])->getPatternsFilePath());
    }

    #[Test]
    public function configurationAndPatternsPathsShareSameBaseDirectory(): void
    {
        $fixtureConfigFactory = $this->getConfigFactory([]);

        self::assertSame(
            dirname($fixtureConfigFactory->getConfigurationPath()),
            dirname($fixtureConfigFactory->getPatternsFilePath()),
        );
    }

    #[Test]
    public function noConfigurationFileFallsBackToTypo3ManagedPatternsBlocklist(): void
    {
        $config = $this->getConfigFactory([])->fromConfigurationFile();

        self::assertArrayHasKey('typo3-managed-patterns', $config->blocklists->patternBackends());
        self::assertArrayHasKey('typo3-blocklist', $config->blocklists->rules());
    }

    #[Test]
    public function floodingDisabledRegistersNoFormFloodRule(): void
    {
        $config = $this->getConfigFactory([])->fromConfigurationFile();

        self::assertArrayNotHasKey('form-flood', $config->fail2ban->rules());
    }

    #[Test]
    public function floodingEnabledRegistersFormFloodRuleWithDefaults(): void
    {
        $config = $this->getConfigFactory(['form' => ['flooding' => ['enable' => true]]])->fromConfigurationFile();

        $rules = $config->fail2ban->rules();
        self::assertArrayHasKey('form-flood', $rules);
        self::assertSame(5, $rules['form-flood']->threshold());
        self::assertSame(60, $rules['form-flood']->period());
        self::assertSame(3600, $rules['form-flood']->banSeconds());
    }

    #[Test]
    public function floodingEnabledUsesConfiguredThresholdPeriodBan(): void
    {
        $config = $this->getConfigFactory(['form' => ['flooding' => [
            'enable' => true,
            'threshold' => 7,
            'period' => 120,
            'ban' => 600,
        ]]])->fromConfigurationFile();

        $rule = $config->fail2ban->rules()['form-flood'];
        self::assertSame(7, $rule->threshold());
        self::assertSame(120, $rule->period());
        self::assertSame(600, $rule->banSeconds());
    }

    #[Test]
    public function configurationFileRulesAreLoadedAndManagedPatternsLayeredOnTop(): void
    {
        $config = $this->getConfigFactory([], 'DefaultConfiguration')->fromConfigurationFile();

        self::assertArrayHasKey('custom-rule', $config->fail2ban->rules());
        self::assertArrayHasKey('typo3-managed-patterns', $config->blocklists->patternBackends());
    }

    #[Test]
    public function formFloodRuleFromConfigurationFileTakesPrecedence(): void
    {
        $config = $this->getConfigFactory(
            ['form' => ['flooding' => ['enable' => true, 'threshold' => 7]]],
            'WithFormFlood',
        )->fromConfigurationFile();

        // File defines form-flood with threshold 99; the generated default (7) must not override it.
        self::assertSame(99, $config->fail2ban->rules()['form-flood']->threshold());
    }

    /**
     * @param array{
     *     form?: array{
     *         flooding?: array{enable?: bool, threshold?: positive-int, period?: positive-int, ban?: positive-int}
     *     }
     * } $extensionConfiguration
     */
    private function getConfigFactory(array $extensionConfiguration, ?string $fixtureName = null): FixtureConfigFactory
    {
        return new FixtureConfigFactory(
            new NoopEventDispatcher(),
            new ExtensionConfiguration($extensionConfiguration),
            null,
            $fixtureName,
        );
    }
}
