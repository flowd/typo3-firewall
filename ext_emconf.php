<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'Firewall for TYPO3',
    'description' => 'Firewall implements a PSR-15 middleware that helps to protect your website against malicious requests',
    'category' => 'fe',
    'author' => 'Sascha Egerer',
    'author_email' => 'sascha.egerer@flowd.de',
    'state' => 'stable',
    'version' => '0.8.0',
    'constraints' => [
        'depends' => [
            'typo3' => '12.4.0-14.4.99',
            'php' => '8.3.0-8.5.99',
        ],
    ],
    'autoload' => [
        'psr-4' => [
            'Flowd\\Typo3Firewall\\' => 'Classes',
        ],
    ],
];
