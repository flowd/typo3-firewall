..  include:: Includes.txt

====================
Features
====================

Key features of the Firewall extension:

- Integration of the Phirewall package (see :doc:`Phirewall`)
- Management of static block patterns in the backend
- Support for various pattern types (IP, CIDR, path, header, user agent, regex)
- Expiration date for patterns (expiresAt)

Configuration overview
----------------------

- Core Phirewall configuration: ``config/system/phirewall.php``
- Static custom patterns managed by the firewall backend module: ``config/system/phirewall.patterns.php``

Usage Examples
==============

Below are practical examples of configuring the firewall in a TYPO3 context.

Blocking common scanner requests and known bot IPs
--------------------------------------------------

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\KeyExtractors;
    use Flowd\Phirewall\Store\RedisCache;
    use Predis\Client;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use Psr\Http\Message\ServerRequestInterface;

    return fn (EventDispatcherInterface $eventDispatcher) =>
    (new Config(
        new RedisCache(new Client('redis://localhost:6379')),
        $eventDispatcher
    ))
        ->blocklist(
            name: 'evil-bot-ips',
            callback: function (ServerRequestInterface $request): bool {
                return in_array(KeyExtractors::ip()($request), [
                    '176.65.149.61',
                    '45.13.214.201',
                ], true);
            }
        )
        ->blocklist(
            name: 'blocked-uri-paths',
            callback: function (ServerRequestInterface $request): bool {
                $path = strtolower($request->getUri()->getPath());
                return str_contains($path, '/wp_admin');
            }
        )
        ->blocklist(
            name: 'blocked-uri-query-strings',
            callback: function (ServerRequestInterface $request): bool {
                $path = strtolower($request->getUri()->getQuery());
                return str_contains($path, 'xdebug')
                    || str_contains($path, 'option=com_');
            }
        );

Temporary blocking after repeated abuse (Fail2Ban)
--------------------------------------------------

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\KeyExtractors;
    use Flowd\Phirewall\Store\RedisCache;
    use Predis\Client;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use Psr\Http\Message\ServerRequestInterface;

    return fn (EventDispatcherInterface $eventDispatcher) =>
    (new Config(
        new RedisCache(new Client('redis://redis:6379')),
        $eventDispatcher
    ))
        ->fail2ban(
            name: 'search-page-scrapers',
            threshold: 5,
            period: 10,
            ban: 60,
            filter: fn (ServerRequestInterface $request) => str_starts_with($request->getUri()->getPath(), '/search'),
            key: KeyExtractors::ip()
        );

Rate limiting with clear client feedback
----------------------------------------

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\KeyExtractors;
    use Flowd\Phirewall\Store\RedisCache;
    use Predis\Client;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return fn (EventDispatcherInterface $eventDispatcher) =>
        (new Config(
            new RedisCache(new Client('redis://localhost:6379')),
            $eventDispatcher
        ))
        ->throttle(
            name: 'slow-down-to-10-requests-in-10-seconds',
            limit: 10,
            period: 10,
            key: KeyExtractors::ip()
        )
        ->enableRateLimitHeaders();

Using APCu as a cache backend
----------------------------

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return fn (EventDispatcherInterface $eventDispatcher) =>
        (new Config(
            new ApcuCache(),
            $eventDispatcher
        ))
        ->blocklist(
            name: 'blocked-uri-paths',
            callback: function (ServerRequestInterface $request): bool {
                $path = strtolower($request->getUri()->getPath());
                return str_contains($path, '/wp_admin');
            }
        );

Using InMemoryCache as a cache backend (not recommended for production)
-----------------------------------------------------------------------

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\InMemoryCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return fn (EventDispatcherInterface $eventDispatcher) =>
        (new Config(
            new InMemoryCache(),
            $eventDispatcher
        ))
        ->blocklist(
            name: 'blocked-uri-paths',
            callback: function (ServerRequestInterface $request): bool {
                $path = strtolower($request->getUri()->getPath());
                return str_contains($path, '/wp_admin');
            }
        );

.. note::

    When using ``InMemoryCache``, only block rules work. Throttling and Fail2Ban do not work as request counts
    cannot be stored between requests. This backend is only suitable for testing or CLI environments,
    not for production use.

Using a custom response for blocked requests
------------------------------------------

With this example, a custom response is returned when a request is blocked.
This can be tested by accessing a blocked path (e.g. ``/wp_admin``).
You should get a 403 response with a custom message.

.. code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\InMemoryCache;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use TYPO3\CMS\Core\Http\ResponseFactory;

    return fn (EventDispatcherInterface $eventDispatcher) =>
        (new Config(
            new InMemoryCache(),
            $eventDispatcher
        ))
        ->blocklist(
            name: 'blocked-uri-paths',
            callback: function (ServerRequestInterface $request): bool {
                $path = strtolower($request->getUri()->getPath());
                return str_contains($path, '/wp_admin');
            }
        )
        ->blocklistedResponse(function ($rule, $type, $serverRequest) {
            return (new ResponseFactory)
                ->createResponse()
                ->withBody((new \TYPO3\CMS\Core\Http\StreamFactory())->createStream('Access denied by firewall rule: ' . $rule . ' (type: ' . $type . ')'))
                ->withHeader('Content-Type', 'text/plain')
                ->withStatus(403);
        });
