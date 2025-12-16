# Application Firewall based on flowd/phirewall

This package provides an application firewall implementation based on the `flowd/phirewall` library.
It includes support for defining custom rules or loading and enforcing rules from the OWASP ModSecurity 
Core Rule Set (CRS) version 4.20.0.

## Features
- Define custom firewall rules using a flexible rule syntax.
- Load and enforce OWASP CRS v4.20.0 rules for web application security.
- Support for common variables, operators, and actions defined in the CRS.
- Integration with PSR-7 HTTP message interfaces for request inspection.
- Configurable diagnostics and observability options.
- Extensible architecture for adding new rules, variables, and operators.

## Installation
You can install this package via Composer:
```bash
composer require flowd/typo3-firewall
```

## Usage
Here is a basic example of how to use the firewall.

Create a Phirewall configuration in your application configuration folder (`/config/system/phirewall.php`).
Please check the "flowd/phirewall" documentation for more details on configuration options.

```php
<?php // /config/system/phirewall.php

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

// Phirewall configuration with ApcuCache for single-server setup.
return fn(EventDispatcherInterface $eventDispatcher) => (new Config(new ApcuCache(), $eventDispatcher))
    ->blocklist(
        name: 'evil-bot-ips',
        callback: function (ServerRequestInterface $request) {
            // block some known evil bot IPs - this is just an example
            return in_array(KeyExtractors::ip()($request), ['176.65.149.61', '45.13.214.201']);
        },
    )->blocklist(
        name: 'blocked-uri-patterns',
        callback: function (ServerRequestInterface $request) {
            $uri = strtolower($request->getUri());
            return str_contains($uri, 'xdebug')
                || str_contains($uri, 'option=com_')
                || str_contains($uri, '/admin/');
        },
    )->fail2ban(
    // Fail2Ban-like rule: block IPs for 1 minute that access /search more than 5 times in 10 seconds
        name: 'search-page-scrapers',
        threshold: 5,
        period: 10,
        ban: 60,
        filter: function (ServerRequestInterface $request) {
            return$request->getUri()->getPath() === '/search';
        },
        key: KeyExtractors::ip()
    )->throttle(
        name: 'slow-down-to-10-requests-in-10-seconds',
        limit: 10,
        period: 10,
        key: KeyExtractors::ip()
    )->enableRateLimitHeaders();
```
