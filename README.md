# TYPO3 Firewall Extension

This extension adds a simple but powerful firewall to your TYPO3 site. It helps protect your website from unwanted traffic, bots, and attacks. You can block or limit requests based on IP, path, or other patterns.

It is built on top of the [phirewall](https://phirewall.de/) package — see the upstream documentation for the full configuration reference.

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

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-wp-admin',
        callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
    );
    return $config;
};
```

## More Examples

### 1. Block Requests from Certain IPs
This example blocks requests from known bad IP addresses using InMemory as the cache backend as no rate limiting is used.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new InMemoryCache(), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-bad-ips',
        callback: fn($request) => in_array($request->getServerParams()['REMOTE_ADDR'] ?? '', [
            '176.65.149.61',
            '45.13.214.201',
        ], true)
    );
    return $config;
};
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

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);
    $config->throttles->add(
        name: 'limit-requests',
        limit: 10,
        period: 10,
        key: KeyExtractors::ip()
    );
    $config->enableRateLimitHeaders();
    return $config;
};
```

### 3. Temporary Blocking After Abuse (Fail2Ban)
This example blocks users for 1 minute if they access `/search` more than 5 times in 10 seconds.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);
    $config->fail2ban->add(
        name: 'block-search-abuse',
        threshold: 5,
        period: 10,
        ban: 60,
        filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/search'),
        key: KeyExtractors::ip()
    );
    return $config;
};
```

### 4. Using Redis as a Cache Backend
This example uses Redis for the cache backend, which is recommended for production and multi-server setups.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\RedisCache;
use Predis\Client;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new RedisCache(new Client('redis://localhost:6379')), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-wp-admin',
        callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
    );
    return $config;
};
```

### 5. Using InMemoryCache (Testing Only)
This example uses InMemoryCache, which is only suitable for testing or CLI environments. Only block rules work; rate limiting and Fail2Ban do not persist between requests.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new InMemoryCache(), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-wp-admin',
        callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
    );
    return $config;
};
// ⚠️ With InMemoryCache, only block rules work. Rate limiting and Fail2Ban do not work between requests.
```

### 6. Custom Response for Blocked Requests
This example shows how to return a custom message and status code when a request is blocked.

```php
<?php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
use Flowd\Phirewall\Store\ApcuCache;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Http\ResponseFactory;
use TYPO3\CMS\Core\Http\StreamFactory;

return function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new ApcuCache(), $eventDispatcher);
    $config->blocklists->add(
        name: 'block-wp-admin',
        callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
    );
    $config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
        fn(string $rule, string $type, $request) => (new ResponseFactory())
            ->createResponse()
            ->withBody((new StreamFactory())->createStream('Access denied by firewall rule: ' . $rule . ' (type: ' . $type . ')'))
            ->withStatus(403)
    );
    return $config;
};
```

## Need More?
- See `Documentation/Examples.rst` for advanced usage and more examples.
- Full phirewall reference: https://phirewall.de/
