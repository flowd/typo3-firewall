<?php

/*
 * This file is part of the TYPO3 CMS extension "firewall".
 *
 * Copyright (C) 2025 Sascha Egerer <sascha.egerer@flowd.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/** @noinspection PhpUndefinedVariableInspection */
$EM_CONF[$_EXTKEY] = [
    'title' => 'Firewall for TYPO3',
    'description' => 'Firewall implements a PSR-15 middleware that helps to protect your website against malicious requests',
    'category' => 'fe',
    'author' => 'Sascha Egerer',
    'author_email' => 'sascha.egerer@flowd.de',
    'state' => 'stable',
    'version' => '0.1.4',
    'constraints' => [
        'depends' => [
            'typo3' => '12.0.0-14.4.99',
            'php' => '8.2.0-8.5.99',
        ],
    ],
    'autoload' => [
        'psr-4' => [
            'Flowd\\Typo3Firewall\\' => 'Classes',
        ],
    ],
];
