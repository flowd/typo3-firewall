<?php

use Flowd\Phirewall\Middleware;

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
    ],
];
