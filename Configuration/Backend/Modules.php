<?php

declare(strict_types=1);

use Flowd\Typo3Firewall\Backend\Controller\FirewallController;

return [
    'system_firewall' => [
        'parent' => 'system',
        'access' => 'admin',
        'path' => '/module/system/firewall',
        'iconIdentifier' => 'module-firewall',
        'labels' => 'LLL:EXT:firewall/Resources/Private/Language/locallang_mod.xlf',
        'extensionName' => 'firewall',
        'inheritNavigationComponentFromMainModule' => false,
        'controllerActions' => [
            FirewallController::class => ['overview', 'create', 'delete', 'prune'],
        ],
    ],
];
