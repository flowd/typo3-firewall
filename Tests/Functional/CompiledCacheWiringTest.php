<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional;

use Flowd\Phirewall\Config;
use Flowd\Typo3Firewall\ConfigFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The disable path and the directory resolution are unit-tested in
 * {@see \Flowd\Typo3Firewall\Tests\Unit\CompiledCacheSettingsTest}; this
 * covers the default DI wiring end to end.
 */
#[CoversClass(ConfigFactory::class)]
final class CompiledCacheWiringTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    #[Test]
    public function theConfigCarriesACompiledDataCacheByDefault(): void
    {
        $config = $this->get(Config::class);

        self::assertNotNull($config->compiledDataCache());
    }
}
