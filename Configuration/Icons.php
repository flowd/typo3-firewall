<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Imaging\IconProvider\BitmapIconProvider;
use TYPO3\CMS\Core\Imaging\IconProvider\SvgIconProvider;

return [
    'module-firewall' => [
        'provider' => SvgIconProvider::class,
        'source' => 'EXT:firewall/Resources/Public/Icons/Extension.svg',
    ],
];
