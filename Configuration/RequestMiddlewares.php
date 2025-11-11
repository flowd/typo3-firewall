<?php
return [
    'frontend' => [
        'flowd/typo3-firewall' => [
            'target' => \Flowd\Phirewall\Middleware::class,
            'after' => [
                'typo3/cms-frontend/timetracker',
            ],
            'before' => [
                'typo3/cms-core/normalized-params-attribute',
            ],
        ],
    ],
];
