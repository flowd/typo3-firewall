<?php

declare(strict_types=1);

defined('TYPO3') or die();

if (!defined('TYPO3_COMPOSER_MODE') || !TYPO3_COMPOSER_MODE) {
    // Resolved via extPath(): ext_localconf.php runs from the concatenated
    // cache file, where __DIR__ points at the cache directory.
    require_once \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath('firewall')
        . 'Resources/Private/Php/ComposerLibraries/vendor/autoload.php';
}

if (\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::isLoaded('form')) {
    \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addTypoScriptSetup(
        'plugin.tx_form.settings.yamlConfigurations.1780296610 = EXT:firewall/Configuration/Form/FloodProtectionSetup.yaml
module.tx_form.settings.yamlConfigurations.1780296610 = EXT:firewall/Configuration/Form/FloodProtectionSetup.yaml'
    );
}
