..  include:: Includes.txt

========
Examples
========

This page collects ready-to-use recipes for common tasks. Each one is a
complete ``config/system/phirewall.php`` file and returns the closure
described in :doc:`Configuration`.

All examples use the ``ApcuCache`` store, the first choice on a single
server. Pick the store that fits your setup on the :doc:`Storage` page.
Rate limiting and bans need a store that keeps state between requests, so
they do not work with the ``InMemoryCache``.

Safelist office and monitoring IPs
==================================

Let trusted clients through before any other rule runs, for example your
office network, an uptime monitor, or a load test runner. A safelist match
ends the check at once, so these clients are never rate limited or banned.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->safelists->ip('office-and-monitoring', [
            '203.0.113.10',
            '198.51.100.0/24',
        ]);

        return $config;
    };

Ban brute-force logins with fail2ban
====================================

Ban a client that posts to the frontend login again and again. A fail2ban
rule counts the requests that match its filter and bans the client once the
threshold is reached. Replace ``/login`` with the path of the page that holds
your felogin form.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->fail2ban->add(
            name: 'felogin-brute-force',
            threshold: 5,
            period: 300,
            ban: 900,
            filter: fn($request) => $request->getMethod() === 'POST'
                && str_starts_with($request->getUri()->getPath(), '/login'),
        );

        return $config;
    };

This bans a client for 15 minutes after 5 login posts within 5 minutes.

Ban request floods with allow2ban
=================================

An allow2ban rule counts every request from a client, not only the ones that
match a filter, and bans the client once it crosses the threshold in the
period. Use it as a blunt guard against request floods. Keep the threshold
well above what a normal visitor reaches, so real people are never caught.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->allow2ban->add(
            name: 'request-flood',
            threshold: 240,
            period: 60,
            banSeconds: 600,
        );

        return $config;
    };

This bans a client for 10 minutes once it sends more than 240 requests in 60
seconds.

Throttle a search or JSON endpoint
==================================

Limit how often a client may call an expensive endpoint, for example a site
search or a JSON API. A throttle allows a fixed number of requests per period
and answers further requests with a 429 response and a ``Retry-After``
header. The scope keeps the counter to the endpoint you name, so browsing the
rest of the site does not add to it.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Config\ClosureRequestMatcher;
    use Flowd\Phirewall\Config\Rule\ThrottleRule;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->throttles->addRule(new ThrottleRule(
            name: 'search-endpoint',
            limit: 20,
            period: 60,
            keyExtractor: null,
            scope: new ClosureRequestMatcher(
                fn($request) => str_starts_with($request->getUri()->getPath(), '/api/search'),
            ),
        ));
        $config->enableRateLimitHeaders();

        return $config;
    };

``enableRateLimitHeaders()`` adds the ``X-RateLimit-*`` headers so clients can
see how much of their budget is left.

Combine a preset with your own rules
====================================

Apply a ready-made preset and add your own rules on top. ``with()`` returns a
new configuration, so assign it back to ``$config``. Rules you add afterwards
run alongside the preset. See :doc:`Presets` for the available packages.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
    use Flowd\PhirewallPresetOwaspCrs\Presets as OwaspPresets;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config = $config->with(OwaspPresets::blocklist(ParanoiaLevel::Level1));

        $config->blocklists->add(
            name: 'cms-scanner-paths',
            callback: fn($request): bool => (bool)preg_match('#^/(wp-admin|wp-login\.php|xmlrpc\.php)(/|$)#i', $request->getUri()->getPath()),
        );

        return $config;
    };

Send a custom response for blocked requests
===========================================

Replace the default 403 body with your own message and headers. The closure
receives the rule name, the rule type, and the request, and returns a PSR-7
response. Keep the 403 status so crawlers and caches treat the request as
blocked.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Config\Response\ClosureBlocklistedResponseFactory;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use TYPO3\CMS\Core\Http\ResponseFactory;
    use TYPO3\CMS\Core\Http\StreamFactory;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->blocklists->add(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp-admin'),
        );

        $config->blocklistedResponseFactory = new ClosureBlocklistedResponseFactory(
            fn(string $rule, string $type, $request) => (new ResponseFactory())
                ->createResponse(403)
                ->withHeader('Content-Type', 'text/plain; charset=utf-8')
                ->withBody((new StreamFactory())->createStream('Blocked by the firewall.')),
        );

        return $config;
    };

Lock the site down temporarily
==============================

Close the site to everyone except a few addresses, for example during
maintenance. The safelist is checked before the blocklist, so listed clients
pass while the catch-all blocklist answers every other request with a 403.
Remove both rules when you are done.

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new ApcuCache();
        $config = new Config($cache, $eventDispatcher);

        $config->safelists->ip('maintenance-access', [
            '203.0.113.10',
        ]);
        $config->blocklists->add(
            name: 'lockdown',
            callback: fn($request) => true,
        );

        return $config;
    };

Forward firewall events to the TYPO3 log
========================================

The extension records events in its own log (see :doc:`Statistics`). To also
send them to the TYPO3 logging framework, register a PSR-14 listener for the
phirewall events. This is a listener class in your own extension or site
package, not part of the ``phirewall.php`` file.

The listener logs every blocked request:

..  code-block:: php

    <?php
    declare(strict_types=1);

    namespace MyVendor\MySitePackage\EventListener;

    use Flowd\Phirewall\Events\BlocklistMatched;
    use Psr\Log\LoggerInterface;

    final class LogBlockedRequests
    {
        public function __construct(
            private readonly LoggerInterface $logger,
        ) {}

        public function __invoke(BlocklistMatched $event): void
        {
            $this->logger->warning('Firewall blocked a request', [
                'rule' => $event->rule,
                'path' => $event->serverRequest->getUri()->getPath(),
            ]);
        }
    }

Register it in your extension's ``Configuration/Services.yaml``:

..  code-block:: yaml

    MyVendor\MySitePackage\EventListener\LogBlockedRequests:
        tags:
            - name: event.listener
              identifier: 'my-firewall-log/blocklist-matched'

TYPO3 reads the event to listen for from the type of the ``__invoke``
argument. On TYPO3 13 you can use the ``#[AsEventListener]`` attribute instead
of the tag. The other events live in the ``Flowd\Phirewall\Events`` namespace,
for example ``ThrottleExceeded`` and ``Fail2BanBanned``.
