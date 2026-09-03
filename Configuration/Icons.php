<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Imaging\IconProvider\SvgIconProvider;
use TYPO3\CMS\Core\Imaging\IconProvider\SvgSpriteIconProvider;

return [
    'module-firewall' => [
        'provider' => SvgIconProvider::class,
        'source' => 'EXT:firewall/Resources/Public/Icons/Extension.svg',
    ],
    'firewall-filter-add' => [
        'provider' => SvgSpriteIconProvider::class,
        'sprite' => 'EXT:firewall/Resources/Public/Icons/FilterAdd.svg#firewall-filter-add',
    ],
    'firewall-filter-remove' => [
        'provider' => SvgSpriteIconProvider::class,
        'sprite' => 'EXT:firewall/Resources/Public/Icons/FilterRemove.svg#firewall-filter-remove',
    ],
];
