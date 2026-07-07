..  include:: Includes.txt

=======
Presets
=======

Presets are ready-made rule bundles. You apply them to your configuration
with ``$config = $config->with(...)``, one line per preset. Note the
assignment: ``with()`` returns the combined configuration instead of
changing ``$config`` in place.

Three preset packages are available. In a Composer-based installation,
install the ones you want (see :doc:`Installation`); the TER package already
bundles all three.

OWASP Core Rule Set
===================

The package ``flowd/phirewall-preset-owasp-crs`` detects common attack
patterns like SQL injection, cross-site scripting, and path traversal,
based on the `OWASP Core Rule Set <https://coreruleset.org/>`__:

..  code-block:: php

    use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
    use Flowd\PhirewallPresetOwaspCrs\Presets as OwaspPresets;

    $config = $config->with(OwaspPresets::blocklist(ParanoiaLevel::Level1));

Start with paranoia level 1. Higher levels detect more, but also produce
more false positives. The fail2ban variant blocks each matching request just
like the blocklist, but additionally bans a client key that keeps matching,
so a repeat offender is locked out for the whole ban period:

..  code-block:: php

    $config = $config->with(OwaspPresets::fail2ban(ParanoiaLevel::Level1, threshold: 5, period: 600, ban: 3600));

The rule set also covers requests for hundreds of sensitive files such as
``.env``, ``.git``, or ``.htpasswd``, so you do not need rules of your own
for those probes.

Bot control
===========

The package ``flowd/phirewall-preset-bots`` controls crawlers by their
User-Agent:

..  code-block:: php

    use Flowd\PhirewallPresetBots\Presets as BotPresets;

    $config = $config->with(
        BotPresets::blockAiCrawlers(),
        BotPresets::throttleSeoCrawlers(limit: 30, period: 60),
    );

This enforces policy for crawlers that identify truthfully. It is not a
defense against hostile scrapers, which can fake any User-Agent.

Known bad IPs
=============

The package ``flowd/phirewall-preset-bad-ips`` blocks requests from a
bundled snapshot of known attacker IP addresses:

..  code-block:: php

    use Flowd\PhirewallPresetBadIps\Presets as BadIpPresets;

    $config = $config->with(BadIpPresets::blocklist());

Blocking CMS scanner paths
==========================

Bots constantly probe paths of other CMS products, for example
``/wp-admin`` or ``/xmlrpc.php``. The OWASP rule set does not block these
paths, because they are legitimate on a WordPress site. On a TYPO3 site they
never are, so a single custom rule handles them:

..  code-block:: php

    $config->blocklists->add(
        name: 'cms-scanner-paths',
        callback: fn($request): bool => (bool)preg_match('#^/(wp-admin|wp-login\.php|wp-content|wp-includes|wordpress|xmlrpc\.php|phpmyadmin)(/|$)#i', $request->getUri()->getPath())
    );

Overriding preset rules
=======================

Every preset rule has a namespaced name, for example ``preset.bots.*``. A
rule that you define later under the same name replaces the preset rule, so
you can adjust single rules without giving up the rest of a preset.
