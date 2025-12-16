<?php

declare(strict_types=1);

/**
 * @see https://github.com/eliashaeussler/typo3-warming/blob/main/Classes/Extension.php
 * Original Copyright (C) 2023 Elias Häußler <elias@haeussler.dev>
 */
/*
 * This file is part of the TYPO3 CMS extension "firewall".
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

namespace Flowd\Typo3Firewall;

use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Utility\GeneralUtility;

final class Extension
{
    /**
     * Load additional libraries provided by PHAR file (only to be used in non-Composer-mode).
     *
     * FOR USE IN ext_localconf.php AND NON-COMPOSER-MODE ONLY.
     */
    public static function loadVendorLibraries(): void
    {
        // Vendor libraries are already available in Composer mode
        if (Environment::isComposerMode()) {
            return;
        }

        $vendorPharFile = GeneralUtility::getFileAbsFileName('EXT:firewall/Resources/Private/Php/vendors.phar');

        if (file_exists($vendorPharFile)) {
            require 'phar://' . $vendorPharFile . '/vendor/autoload.php';
        }
    }
}
