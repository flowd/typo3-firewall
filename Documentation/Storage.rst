..  include:: Includes.txt

=======
Storage
=======

Rate limiting and bans need a store that persists counters between requests.
The store is the first argument of the ``Config`` object in your
configuration file (see :doc:`Configuration`).

Which store should I use?
=========================

==================  ============================================================
``ApcuCache``       First choice on a single server. Needs the APCu extension.
``RedisCache``      First choice for multi-server setups. Needs a Redis server.
``PdoCache``        Works without extra services, but opens a database
                    connection for every request. Fallback only.
``InMemoryCache``   Testing only. Nothing persists between requests.
==================  ============================================================

Prefer ``ApcuCache`` or ``RedisCache``. The firewall runs before TYPO3
boots, and with these stores a blocked request is answered without touching
the database at all. ``PdoCache`` opens a database connection for every
request, including the ones the firewall blocks, so an attack still creates
load on the database, which is exactly what the firewall should prevent.

The TYPO3 caching framework cannot be used as a store: it does not implement
PSR-16 and does not offer the atomic counters the firewall needs.

ApcuCache: single-server setups
===============================

..  code-block:: php

    use Flowd\Phirewall\Store\ApcuCache;

    $cache = new ApcuCache();

APCu keeps counters in the memory of the PHP process manager. This is the
fastest option, but the counters are per server: do not use it behind a load
balancer, and note that a PHP restart clears all counters and bans.

RedisCache: multi-server setups
===============================

..  code-block:: php

    use Flowd\Phirewall\Store\RedisCache;
    use Predis\Client;

    $cache = new RedisCache(new Client('redis://localhost:6379'));

All servers share the same counters and bans. Requires the
``predis/predis`` package:

..  code-block:: bash

    composer require predis/predis

..  note::

    The TER package does not bundle ``predis/predis``. In a classic
    installation you can still use ``RedisCache`` when you install Predis
    yourself and take care of its autoloading. Otherwise use ``ApcuCache``
    on a single server or ``PdoCache`` for multi-server setups.

PdoCache: the TYPO3 database
============================

``PdoCache`` stores its counters in a table of the TYPO3 database, using
the connection settings of your installation, and creates that table on its
own. It needs no additional service, which makes it the fallback when
neither APCu nor Redis is available. Keep the performance cost from above
in mind: every request opens a database connection before the firewall can
block it.

..  code-block:: php

    use Flowd\Phirewall\Store\PdoCache;
    use TYPO3\CMS\Core\Database\ConnectionPool;
    use TYPO3\CMS\Core\Utility\GeneralUtility;

    $cache = new PdoCache(GeneralUtility::makeInstance(ConnectionPool::class)->getConnectionForTable('phirewall_cache')->getNativeConnection());

..  warning::

    ``PdoCache`` needs a ``PDO`` object, so the TYPO3 database connection
    must use a PDO driver such as ``pdo_mysql``. With the ``mysqli`` driver,
    ``getNativeConnection()`` returns a ``mysqli`` object and the firewall
    configuration fails.

    Check the ``driver`` entry of your connection in
    ``config/system/settings.php``. Either switch it to ``pdo_mysql``, or
    keep it and map the firewall table to a separate connection with a PDO
    driver:

    ..  code-block:: php

        // config/system/additional.php
        $GLOBALS['TYPO3_CONF_VARS']['DB']['Connections']['phirewall'] = array_merge(
            $GLOBALS['TYPO3_CONF_VARS']['DB']['Connections']['Default'],
            ['driver' => 'pdo_mysql']
        );
        $GLOBALS['TYPO3_CONF_VARS']['DB']['TableMapping']['phirewall_cache'] = 'phirewall';

TYPO3 does not know this table, so the database analyzer in the install tool
treats it as unused and offers to remove it, and with it all counters and
bans. You must declare the table in the ``ext_tables.sql`` of your site
package so TYPO3 knows it:

..  code-block:: sql

    CREATE TABLE phirewall_cache (
        cache_key varchar(255) NOT NULL,
        cache_value text NOT NULL,
        expires_at bigint(20) DEFAULT NULL,
        PRIMARY KEY (cache_key)
    );

InMemoryCache: testing only
===========================

..  code-block:: php

    use Flowd\Phirewall\Store\InMemoryCache;

    $cache = new InMemoryCache();

Counters live only for the current request. Block rules work, but rate
limiting and bans do not, and the blocked keys view in the
:doc:`backend module <BackendModule>` always stays empty. Use it for local
experiments or setups that only need static block rules.
