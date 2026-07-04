..  include:: Includes.txt

====================
Examples
====================

Key features of the Firewall extension:

- Integration of the Phirewall package (see :doc:`Phirewall`)
- Management of static block patterns in the backend
- Support for various pattern types (IP, CIDR, path, header, regex)
- Expiration date for patterns (expiresAt)

Configuration overview
----------------------

- Core Phirewall configuration: ``config/system/phirewall.php``
- Static custom patterns managed by the firewall backend module: ``config/system/phirewall.patterns.json``

Usage Examples
==============

Below are practical examples of configuring the firewall in a TYPO3 context.

The extension sets the client IP resolver for you: ``ConfigFactory`` defaults it to
``GeneralUtility::getIndpEnv('REMOTE_ADDR')``, which applies TYPO3's ``reverseProxyIP``
setting. Rules see the real client IP behind a reverse proxy or CDN, and rate limiting
and Fail2Ban count per client IP without a key extractor. When no client IP can be
resolved, the resolver returns ``null`` and rules that key on the client IP skip the
request. Only call ``$config->setIpResolver()`` yourself if you need a different
resolution.

Blocking common scanner requests and known bot IPs
--------------------------------------------------

This example blocks requests from known bad IP addresses and certain paths or query strings. It uses InMemoryCache, which is fine for simple blocklists (no rate limiting).

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\InMemoryCache;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use Psr\Http\Message\ServerRequestInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new InMemoryCache(), $eventDispatcher);
        $config->blocklists->ip('evil-bot-ips', [
            '176.65.149.61',
            '45.13.214.201',
        ]);
        $config->blocklists->add(
            name: 'blocked-uri-paths',
            callback: fn(ServerRequestInterface $request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
        $config->blocklists->add(
            name: 'blocked-uri-query-strings',
            callback: fn(ServerRequestInterface $request) => str_contains(strtolower($request->getUri()->getQuery()), 'xdebug')
                || str_contains(strtolower($request->getUri()->getQuery()), 'option=com_')
        );
        return $config;
    };

Temporary blocking after repeated abuse (Fail2Ban)
--------------------------------------------------

This example blocks users for 1 minute if they access `/search` more than 5 times in 10 seconds. Requires a persistent cache backend like APCu or Redis.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new ApcuCache(), $eventDispatcher);
        $config->fail2ban->add(
            name: 'search-page-scrapers',
            threshold: 5,
            period: 10,
            ban: 60,
            filter: fn($request) => str_starts_with($request->getUri()->getPath(), '/search')
        );
        return $config;
    };

Rate limiting with clear client feedback
----------------------------------------

This example limits users to 10 requests every 10 seconds (per IP) and sends rate limit headers. Requires a persistent cache backend like APCu or Redis.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new ApcuCache(), $eventDispatcher);
        $config->throttles->add(
            name: 'slow-down-to-10-requests-in-10-seconds',
            limit: 10,
            period: 10
        );
        $config->enableRateLimitHeaders();
        return $config;
    };

Using APCu as a cache backend
-----------------------------

This example shows how to use APCu as a cache backend. Use this for single-server setups.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new ApcuCache(), $eventDispatcher);
        $config->blocklists->add(
            name: 'blocked-uri-paths',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
        return $config;
    };

Using Redis as a cache backend
------------------------------

This example uses Redis for the cache backend, which is recommended for production and multi-server setups.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\RedisCache;
    use Predis\Client;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new RedisCache(new Client('redis://localhost:6379')), $eventDispatcher);
        $config->blocklists->add(
            name: 'blocked-uri-paths',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
        return $config;
    };

Using InMemoryCache as a cache backend (not recommended for production)
-----------------------------------------------------------------------

This example uses InMemoryCache, which is only suitable for testing or CLI environments. Only block rules work; rate limiting and Fail2Ban do not persist between requests.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\InMemoryCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new InMemoryCache(), $eventDispatcher);
        $config->blocklists->add(
            name: 'blocked-uri-paths',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
        return $config;
    };

.. note::

    When using ``InMemoryCache``, only block rules work. Throttling and Fail2Ban do not work as request counts
    cannot be stored between requests. This backend is only suitable for testing or CLI environments,
    not for production use.

Using a custom response for blocked requests
--------------------------------------------

This example shows how to return a custom message and status code when a request is blocked.

.. code-block:: php

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
            name: 'blocked-uri-paths',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp_admin')
        );
        $config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
            fn(string $rule, string $type, $request) => (new ResponseFactory())
                ->createResponse()
                ->withBody((new StreamFactory())->createStream('Access denied by firewall rule: ' . $rule . ' (type: ' . $type . ')'))
                ->withHeader('Content-Type', 'text/plain')
                ->withStatus(403)
        );
        return $config;
    };
