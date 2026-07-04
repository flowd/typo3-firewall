# TYPO3 Firewall Extension

This extension adds a simple but powerful firewall to your TYPO3 site. It helps protect your website from unwanted traffic, bots, and attacks. You can block or limit requests based on IP, path, or other patterns.

It is built on top of the [phirewall](https://phirewall.de/) package.

## Key Features
- Block requests from specific IPs or patterns
- Limit how often users can access certain pages (rate limiting)
- Temporarily block users after repeated abuse (like Fail2Ban)
- Easy to configure with PHP
- Works with Redis, APCu, or in-memory cache

## Installation
Install with Composer:

```bash
composer require flowd/typo3-firewall
```

## Quick Start
Add a file at `config/system/phirewall.php` in your TYPO3 project. This example blocks requests to `/wp_admin` using APCu as the cache backend.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-wp-admin',
        callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
    );
    return $config;
};
```

## Documentation
- [Extension documentation](https://docs.typo3.org/p/flowd/typo3-firewall/main/en-us/Index.html): configuration, examples, and the backend module (source in `Documentation/`)
- [Phirewall reference](https://phirewall.de/): all rule types, stores, and advanced features
