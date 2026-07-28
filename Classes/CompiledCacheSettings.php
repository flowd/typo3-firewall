<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;

/**
 * Typed access to the compiled-data cache settings from the extension
 * configuration.
 *
 * The compiled-data cache lets preset packages (OWASP CRS, bad IPs) skip
 * re-parsing their large data sources on every request. It is on by default
 * and writes compiled PHP artifacts to the TYPO3 code cache directory.
 */
final class CompiledCacheSettings
{
    public function __construct(
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    public function isEnabled(): bool
    {
        return (bool)$this->getSetting('compiledCacheEnabled', '1');
    }

    /**
     * The directory for the compiled artifacts. A non-empty configured value
     * wins; otherwise the TYPO3 code cache directory is used, which lives in
     * var/ outside the web root and is writable by the runtime.
     */
    public function getDirectory(): string
    {
        $configured = trim($this->getSetting('compiledCacheDirectory', ''));
        if ($configured !== '') {
            return $configured;
        }

        return Environment::getVarPath() . '/cache/code/firewall';
    }

    private function getSetting(string $settingName, string $default): string
    {
        try {
            $value = $this->extensionConfiguration->get('firewall', $settingName);
        } catch (\Throwable) {
            return $default;
        }

        return is_scalar($value) ? (string)$value : $default;
    }
}
