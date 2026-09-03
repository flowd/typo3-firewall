..  include:: Includes.txt

============
Installation
============

Requirements
============

===================  ===============================
Extension version    0.9
TYPO3                12.4 LTS, 13.4 LTS, 14
PHP                  8.3, 8.4, 8.5
Firewall engine      flowd/phirewall 0.10
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

With the TYPO3 reports module installed, the firewall adds two checks to
:guilabel:`System > Status`: a PCRE JIT check that warns when PCRE JIT is
disabled or unavailable (the firewall evaluates regular expression patterns
on every request, so matching would fall back to the slower interpreter),
and a privacy check that warns while the ``eventLogFullIpRules`` exception
stores unanonymized client IPs (see :doc:`Statistics`).

..  code-block:: bash

    composer require typo3/cms-reports

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

Upgrade from 0.8
================

Version 0.9 extends the event log and fixes the client IP resolution.
Review these points when upgrading:

Database schema and caches
    Update the database schema (a new index on ``tx_firewall_event``) and
    flush all caches after the upgrade, for example with
    ``vendor/bin/typo3 extension:setup`` followed by
    ``vendor/bin/typo3 cache:flush``.

The event log view defaults to the last 7 days
    Older entries stay recorded and reachable through the new "All" time
    range button.

The firewall middleware moved after the normalized params
    The middleware now runs after ``typo3/cms-core/normalized-params-attribute``
    (and before site resolution), so the ``reverseProxyIP`` settings apply
    to every IP-keyed rule. Review site packages that order their own
    middlewares relative to the firewall.

New opt-in event log settings
    ``eventLogFullIpRules`` and ``eventLogRequestHeaders`` record more data
    for attack analysis and are off by default; see :doc:`Statistics` before
    enabling them.

Upgrade from 0.7
================

Version 0.8 changes what the event log records. Review these points when
upgrading:

POST parameters are no longer stored
    Event log entries record the metadata of the match itself (rule,
    counters, matched target and value) instead of the submitted POST
    parameters. The ``eventLogMaskParameters`` extension setting was removed
    together with the parameter storage; a leftover value in the extension
    configuration is ignored.

The track_hit event type is deprecated
    Track events are recorded as ``track_matched`` (every hit of a track
    rule, high volume) or ``track_threshold_reached`` (a track rule with a
    limit reached it). Replace ``track_hit`` in the ``eventLogTypes``
    extension setting with one or both of the new types; until then the
    deprecated value keeps enabling both and logs a deprecation.

New default event log types
    The default ``eventLogTypes`` now include ``track_threshold_reached``.
    Installations without an explicit type list start recording an entry
    when a track rule with a limit reaches it.

Upgrade from 0.3
================

Version 0.4 updates the firewall engine from phirewall 0.3 to 0.8. Review
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

Fail2Ban blocks every matching request
    A fail2ban rule answers **every** request its filter matches with a
    ``403``, not only the request that reaches the threshold; the threshold
    controls when the client is banned outright. If a rule in your
    ``phirewall.php`` filters on something a legitimate request can carry
    (for example every POST to a login path), move it to an allow2ban rule
    with the same filter, which counts the matches but lets them pass until
    the threshold. Rules that match only clearly malicious traffic (scanner
    paths) block the probe on sight. Rules driven by
    ``RequestContext::recordFailure()`` (an empty filter) are unaffected.

New event type ``fail2ban_matched``
    A blocked-but-not-yet-banned fail2ban match is recorded as the new event
    type ``fail2ban_matched`` and counts towards the blocking statistics. It
    is enabled by default; adjust the logged types in the extension
    configuration if you do not want it.

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
