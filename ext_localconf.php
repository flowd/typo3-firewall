<?php

declare(strict_types=1);

defined('TYPO3') or die();

// Register the FloodProtection finisher form configuration the classic way:
//   plugin.tx_form  -> frontend rendering
//   module.tx_form  -> backend form editor
// (TYPO3 v14.2+ deprecates this in favour of Configuration/Form/<Set>/config.yaml
// auto-discovery, but the TypoScript paths are still honoured until v15.)
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addTypoScriptSetup(
    'plugin.tx_form.settings.yamlConfigurations.1780296610 = EXT:firewall/Configuration/Form/FloodProtectionSetup.yaml
module.tx_form.settings.yamlConfigurations.1780296610 = EXT:firewall/Configuration/Form/FloodProtectionSetup.yaml'
);
