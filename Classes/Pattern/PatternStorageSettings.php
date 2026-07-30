<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Flowd\Typo3Firewall\ConfigFactory;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Typed access to the pattern storage settings from the extension
 * configuration.
 *
 * The backend module persists its managed patterns as a JSON file with a
 * lock file next to it. By default both live beside phirewall.php; the
 * directory is configurable for setups where that location is read-only
 * at runtime. A configured directory must lie within the TYPO3 project
 * directory or BE/lockRootPath.
 */
final class PatternStorageSettings
{
    private const string PATTERNS_FILE_NAME = 'phirewall.patterns.json';

    public function __construct(
        private readonly ExtensionConfiguration $extensionConfiguration,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function getPatternsFilePath(): string
    {
        return $this->getDirectory() . '/' . self::PATTERNS_FILE_NAME;
    }

    /**
     * The directory for the patterns file and its lock file. A non-empty
     * configured value wins when it lies within the allowed TYPO3 paths;
     * otherwise the files live next to phirewall.php in config/system.
     */
    public function getDirectory(): string
    {
        $configured = rtrim(trim($this->getSetting('patternsDirectory', '')), '/');
        if ($configured === '') {
            return $this->getDefaultDirectory();
        }

        if (!GeneralUtility::isAllowedAbsPath($configured)) {
            $this->logger?->warning(
                'The configured firewall patterns directory is outside the TYPO3 project directory and BE/lockRootPath, using the default directory instead.',
                ['configuredDirectory' => $configured]
            );
            return $this->getDefaultDirectory();
        }

        return $configured;
    }

    private function getDefaultDirectory(): string
    {
        return ConfigFactory::getBaseConfigPath() . '/system';
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
