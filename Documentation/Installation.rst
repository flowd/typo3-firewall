..  include:: Includes.txt

============
Installation
============

Requirements
============

===================  ===============================
Extension version    0.4
TYPO3                12.4 LTS, 13.4 LTS, 14
PHP                  8.3, 8.4, 8.5
Firewall engine      flowd/phirewall 0.7
===================  ===============================

The firewall works with every database supported by TYPO3. Rate limiting and
bans additionally need one of the stores described in :doc:`Storage`.

Installation with Composer
==========================

..  code-block:: bash

    composer require flowd/typo3-firewall

Then activate the extension:

..  code-block:: bash

    vendor/bin/typo3 extension:setup

The frontend middleware is registered automatically. Continue with
:doc:`QuickStart` to create your first configuration file.

Optional packages
-----------------

Three preset packages add ready-made protection rules (see :doc:`Presets`):

..  code-block:: bash

    composer require flowd/phirewall-preset-owasp-crs
    composer require flowd/phirewall-preset-bots
    composer require flowd/phirewall-preset-bad-ips

The dashboard widgets need the TYPO3 dashboard:

..  code-block:: bash

    composer require typo3/cms-dashboard

Installation without Composer (TER)
===================================

Install the extension from the
`TYPO3 Extension Repository <https://extensions.typo3.org/extension/firewall/>`__
using the extension manager, then activate it.

The TER package bundles everything the firewall needs: the phirewall library,
the three preset packages, and ``psr/simple-cache``. They live inside the
extension under ``Resources/Private/Php/ComposerLibraries`` and are loaded
automatically. No extra installation step is needed, and the presets are
available without further setup.

Upgrade from 0.3
================

Version 0.4 updates the firewall engine from phirewall 0.3 to 0.7. Review
these points when upgrading:

New database table
    Version 0.4 records firewall events in the new table
    ``tx_firewall_event``. Update the database schema after the upgrade,
    for example with ``vendor/bin/typo3 extension:setup``.

Counters and bans reset once
    phirewall 0.5 changed its internal cache key format. Active bans and
    running rate limit counters are forgotten one time when you deploy the
    upgrade. They rebuild automatically with the next matching requests.

Bans trigger at the threshold
    A fail2ban or allow2ban rule now bans when the threshold is reached, not
    one request later. With ``threshold: 5`` the ban starts at the fifth
    matching request. Lower your thresholds by one if you relied on the old
    behavior.

``$config->blocklists->owasp()`` was removed
    The OWASP rule engine moved into the package
    ``flowd/phirewall-preset-owasp-crs``. See :doc:`Presets` for the new way
    to enable it.

``$config->safelists->trustedBots()`` was removed
    Wire the matcher directly instead::

        $config->safelists->addRule(new \Flowd\Phirewall\Config\Rule\SafelistRule(
            'trusted-bots',
            new \Flowd\Phirewall\Matchers\TrustedBotMatcher(cache: $cache)
        ));

``KeyExtractors::ip()`` is deprecated
    Leave out the ``key`` argument of throttle, fail2ban, allow2ban, and
    track rules. They then count per client IP resolved through TYPO3
    (see :doc:`TrustedProxies`).
