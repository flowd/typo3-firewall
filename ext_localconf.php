<?php

declare(strict_types=1);

defined('TYPO3') or die();

// Register the form configuration so the FloodProtection finisher is available
// in the form editor and at runtime. Uses module.tx_form.settings, which the
// Form Framework reads for both the backend editor and frontend rendering.
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addTypoScriptSetup(
'module.tx_form {
    settings {
        yamlConfigurations {
            1780296610 = EXT:firewall/Configuration/Form/FloodProtectionSetup.yaml
        }
    }
}'
);
