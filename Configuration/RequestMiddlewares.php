<?php

use Flowd\Phirewall\Middleware;
use Flowd\Typo3Firewall\Middleware\AttachFirewallToTypo3ContextMiddleware;

return [
    'frontend' => [
        'flowd/typo3-firewall' => [
            'target' => Middleware::class,
            'after' => [
                'typo3/cms-frontend/timetracker',
            ],
            'before' => [
                'typo3/cms-core/normalized-params-attribute',
            ],
        ],
        'flowd/typo3-firewall-aspect' => [
            'target' => AttachFirewallToTypo3ContextMiddleware::class,
            'disabled' => true,
            'after' => [
                'flowd/typo3-firewall',
            ],
            'before' => [
                'typo3/cms-core/normalized-params-attribute',
            ],
        ],
    ],
];
