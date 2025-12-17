# TYPO3 Firewall Extension

This extension adds a simple but powerful firewall to your TYPO3 site. It helps protect your website from unwanted traffic, bots, and attacks. You can block or limit requests based on IP, path, or other patterns.

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

## Quick Start Example
Add a file at `config/system/phirewall.php` in your TYPO3 project. This example blocks requests to `/wp_admin` using APCu as the cache backend.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new ApcuCache(), $eventDispatcher))
        ->blocklist(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
```

## More Examples

### 1. Block Requests from Certain IPs
This example blocks requests from known bad IP addresses using InMemory as the cache backend as no rate limiting is used.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new InMemoryCache(), $eventDispatcher))
        ->blocklist(
            name: 'block-bad-ips',
            callback: fn($request) => in_array($request->getServerParams()['REMOTE_ADDR'] ?? '', [
                '176.65.149.61',
                '45.13.214.201',
            ], true)
        );
```

### 2. Rate Limiting
This example limits users to 10 requests every 10 seconds (per IP) and sends rate limit headers.
This requires a cache backend that persists between requests, like APCu or Redis.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new ApcuCache(), $eventDispatcher))
        ->throttle(
            name: 'limit-requests',
            limit: 10,
            period: 10,
            key: KeyExtractors::ip()
        )
        ->enableRateLimitHeaders();
```

### 3. Temporary Blocking After Abuse (Fail2Ban)
This example blocks users for 1 minute if they access `/search` more than 5 times in 10 seconds.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new ApcuCache(), $eventDispatcher))
        ->fail2ban(
            name: 'block-search-abuse',
            threshold: 5,
            period: 10,
            ban: 60,
            filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/search'),
            key: KeyExtractors::ip()
        );
```

### 4. Using Redis as a Cache Backend
This example uses Redis for the cache backend, which is recommended for production and multi-server setups.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new RedisCache(new Client('redis://localhost:6379')), $eventDispatcher))
        ->blocklist(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
```

### 5. Using InMemoryCache (Testing Only)
This example uses InMemoryCache, which is only suitable for testing or CLI environments. Only block rules work; rate limiting and Fail2Ban do not persist between requests.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new InMemoryCache(), $eventDispatcher))
        ->blocklist(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
// ⚠️ With InMemoryCache, only block rules work. Rate limiting and Fail2Ban do not work between requests.
```

### 6. Custom Response for Blocked Requests
This example shows how to return a custom message and status code when a request is blocked.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Http\ResponseFactory;
use TYPO3\CMS\Core\Http\StreamFactory;

return fn(EventDispatcherInterface $eventDispatcher) =>
    (new Config(new ApcuCache(), $eventDispatcher))
        ->blocklist(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        )
        ->blocklistedResponse(function ($rule, $type, $request) {
            return (new ResponseFactory())
                ->createResponse()
                ->withBody((new StreamFactory())->createStream('Access denied by firewall rule: ' . $rule . ' (type: ' . $type . ')'))
                ->withStatus(403);
        });
```

## Need More?
See `Documentation/Examples.rst` for advanced usage and more examples.
