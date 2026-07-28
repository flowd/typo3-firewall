<?php

declare(strict_types=1);

/**
 * Adds the PSR-4 autoload entries for the bundled composer libraries to
 * ext_emconf.php. Used by the release workflow before packaging the artefact.
 */

$extEmConfFile = dirname(__DIR__, 2) . '/ext_emconf.php';

$vendorAutoload = [
    'Flowd\\Phirewall\\' => 'Resources/Private/Php/ComposerLibraries/vendor/flowd/phirewall/src/',
    'Flowd\\PhirewallPresetOwaspCrs\\' => 'Resources/Private/Php/ComposerLibraries/vendor/flowd/phirewall-preset-owasp-crs/src/',
    'Flowd\\PhirewallPresetBots\\' => 'Resources/Private/Php/ComposerLibraries/vendor/flowd/phirewall-preset-bots/src/',
    'Flowd\\PhirewallPresetBadIps\\' => 'Resources/Private/Php/ComposerLibraries/vendor/flowd/phirewall-preset-bad-ips/src/',
    'Psr\\SimpleCache\\' => 'Resources/Private/Php/ComposerLibraries/vendor/psr/simple-cache/src/',
];

$EM_CONF = [];
$_EXTKEY = 'firewall';
require $extEmConfFile;

$configuration = $EM_CONF[$_EXTKEY] ?? null;
if (!is_array($configuration) || !is_array($configuration['autoload']['psr-4'] ?? null)) {
    fwrite(STDERR, 'Unexpected configuration structure in ' . $extEmConfFile . PHP_EOL);
    exit(1);
}

if (array_intersect_key($configuration['autoload']['psr-4'], $vendorAutoload) !== []) {
    fwrite(STDERR, 'Vendor autoload entries are already present in ' . $extEmConfFile . PHP_EOL);
    exit(1);
}

$configuration['autoload']['psr-4'] += $vendorAutoload;

$fileContent = "<?php\n\n\$EM_CONF[\$_EXTKEY] = " . var_export($configuration, true) . ";\n";

if (file_put_contents($extEmConfFile, $fileContent) === false) {
    fwrite(STDERR, 'Unable to write ' . $extEmConfFile . PHP_EOL);
    exit(1);
}

echo 'Added vendor autoload entries to ' . $extEmConfFile . PHP_EOL;
