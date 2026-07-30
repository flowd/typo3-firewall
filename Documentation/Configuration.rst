..  include:: Includes.txt

=============
Configuration
=============

The configuration file
======================

The firewall is configured in one PHP file:

- Composer-based installation: ``config/system/phirewall.php``
- Classic installation: ``typo3conf/system/phirewall.php``

The file returns a closure. The closure receives the TYPO3 event dispatcher
and returns a configured ``Flowd\Phirewall\Config`` object:

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\PdoCache;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use TYPO3\CMS\Core\Database\ConnectionPool;
    use TYPO3\CMS\Core\Utility\GeneralUtility;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        // 1. The store keeps counters for rate limiting and bans. See the Storage page.
        $cache = new PdoCache(GeneralUtility::makeInstance(ConnectionPool::class)->getConnectionForTable('phirewall_cache')->getNativeConnection());

        $config = new Config($cache, $eventDispatcher);

        // 2. Add your rules here.
        $config->blocklists->add(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp-admin')
        );

        return $config;
    };

The closure receives the TYPO3 event dispatcher. Pass it to the ``Config``
object as shown above; the effective configuration always uses the TYPO3
event dispatcher, so event logging and the :doc:`Statistics` view work even
when your file does not pass it on.

All rule types (safelists, blocklists, throttles, fail2ban, allow2ban,
tracks) and their options are documented in the
`phirewall documentation <https://phirewall.de/>`__. They work exactly the
same way inside this file. See :doc:`Examples` for TYPO3 recipes.

What the extension adds automatically
=====================================

The extension builds its defaults first and merges your configuration file
on top. Your file wins on every name clash, so it can override each default
by using its name.

Client IP resolver
    When your configuration does not call ``$config->setIpResolver()``, the
    extension sets a resolver that uses
    ``GeneralUtility::getIndpEnv('REMOTE_ADDR')``. This applies TYPO3's
    ``reverseProxyIP`` settings, so rules see the real visitor address behind
    a reverse proxy or CDN. When no address can be resolved, the resolver
    returns ``null`` and rules that key on the client IP skip the request.
    Details: :doc:`TrustedProxies`.

Backend managed block patterns
    The block patterns from the :doc:`backend module <BackendModule>` are
    added first as the blocklist rule ``typo3-blocklist``, and they stay
    active even when your configuration file is missing. A rule with the
    same name in your file replaces them, so only define a rule named
    ``typo3-blocklist`` when you want to take over the backend managed
    patterns yourself. The patterns live in
    ``config/system/phirewall.patterns.json`` next to ``phirewall.php``;
    point the extension configuration setting ``patternsDirectory`` at
    another directory when that location is read-only at runtime. The
    file's lock file is created in the same directory. The directory must
    lie within the TYPO3 project directory or within
    ``$GLOBALS['TYPO3_CONF_VARS']['BE']['lockRootPath']``; other values
    are ignored with a logged warning and the default directory is used.

Compiled-data cache
    Preset packages such as OWASP CRS and the bad-IP list parse large data
    sources when a rule first evaluates. Under PHP-FPM that parsing would run
    on every request. The extension gives the ``Config`` a compiled-data
    cache so the parsed data is served from OPcache-backed artifacts and
    re-parsed only when a source file changes. It is on by default and writes
    to ``var/cache/code/firewall`` (outside the web root). Turn it off or point
    it at another directory in the extension configuration
    (``compiledCacheEnabled``, ``compiledCacheDirectory``). If the directory
    cannot be created the extension logs a warning; a directory that exists
    but is not writable degrades silently. Either way the presets fall back to
    per-request parsing, so the firewall keeps working.

Behavior without a configuration file
=====================================

When the file is missing, the extension falls back to a default
configuration. When the file exists but is broken, the extension logs the
problem and uses the same fallback: a warning when the file does not return
a closure or the closure does not return a ``Config`` object, an error when
loading the file fails, for example with a syntax error or an exception:

- Store: ``InMemoryCache`` (nothing persists between requests)
- Rules: only the backend managed block patterns

The website keeps working. Note that rate limiting and bans need a real
store, so create the configuration file for any protection beyond static
block patterns.
