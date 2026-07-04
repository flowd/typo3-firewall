..  include:: Includes.txt

===========
Quick start
===========

Follow these steps to get a working firewall in a Composer based TYPO3
project.

1. Install the extension
========================

..  code-block:: bash

    composer require flowd/typo3-firewall

The frontend middleware is registered automatically. Without a configuration
file the firewall only enforces the block patterns managed in the backend
module.

2. Create the configuration file
================================

Create the file ``config/system/phirewall.php``. This minimal example blocks
requests for paths that only scanners ask for:

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\Store\PdoCache;
    use Psr\EventDispatcher\EventDispatcherInterface;
    use TYPO3\CMS\Core\Database\ConnectionPool;
    use TYPO3\CMS\Core\Utility\GeneralUtility;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $cache = new PdoCache(GeneralUtility::makeInstance(ConnectionPool::class)->getConnectionForTable('phirewall_cache')->getNativeConnection());
        $config = new Config($cache, $eventDispatcher);

        $config->blocklists->add(
            name: 'block-wp-admin',
            callback: fn($request) => str_starts_with(strtolower($request->getUri()->getPath()), '/wp-admin')
        );

        return $config;
    };

The extension resolves the client IP for you through TYPO3, so the firewall
sees the real visitor address behind a reverse proxy or CDN
(see :doc:`TrustedProxies`).

3. Verify it works
==================

Request a blocked path. The firewall answers with status 403:

..  code-block:: bash

    curl -i https://www.example.org/wp-admin/setup.php

Regular pages keep working as before.

Next steps
==========

- Add rate limiting, bans, and presets: :doc:`Configuration` and :doc:`Presets`
- Pick the right store for your hosting: :doc:`Storage`
- Manage block patterns and see statistics in the backend: :doc:`BackendModule` and :doc:`Statistics`
