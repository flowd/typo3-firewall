..  include:: Includes.txt

===============
Trusted proxies
===============

Why this matters
================

Rules that work with the client IP (IP blocklists, rate limiting, bans) need
the real visitor address. Behind a reverse proxy, a load balancer, or a CDN,
the connecting address is the proxy, not the visitor. Without correct
resolution, two things go wrong:

- Every visitor appears as the same proxy IP. One ban then blocks everyone.
- An attacker is not banned, because the counted address is the proxy.

The default: TYPO3 resolves the client IP
==========================================

The extension resolves the client IP through
``GeneralUtility::getIndpEnv('REMOTE_ADDR')``. This applies the reverse
proxy settings of your TYPO3 installation. Configure them once in
``config/system/settings.php`` (classic installation:
``typo3conf/system/settings.php``) and both TYPO3 and the firewall see the
real visitor address:

..  code-block:: php

    // config/system/settings.php
    'SYS' => [
        'reverseProxyIP' => '203.0.113.10',   // the address of your proxy
        'reverseProxyHeaderMultiValue' => 'last',
    ],

Details on these settings:
`TYPO3 reverse proxy configuration <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/Configuration/Typo3ConfVars/SYS.html#confval-globals-typo3-conf-vars-sys-reverseproxyip>`__.

Without a proxy in front of your website no configuration is needed: the
connecting address is already the visitor.

When no address can be resolved, the resolver returns ``null`` and rules
that key on the client IP skip the request.

Using a different resolver
==========================

Call ``$config->setIpResolver()`` in your configuration file to override the
default, for example to use the phirewall ``TrustedProxyResolver`` with its
own trust list:

..  code-block:: php

    use Flowd\Phirewall\Http\TrustedProxyResolver;
    use Flowd\Phirewall\KeyExtractors;

    $config->setIpResolver(KeyExtractors::clientIp(new TrustedProxyResolver(['10.0.0.0/8'])));

This is only needed when the TYPO3 settings cannot express your setup. The
resolver options are documented in the
`phirewall documentation <https://phirewall.de/>`__.

Verify the resolution
=====================

Add a temporary blocklist rule for your own IP address and request the
website through the proxy:

..  code-block:: php

    $config->blocklists->ip('verify-my-ip', '198.51.100.7');

When the request is blocked (status 403), the firewall sees your real
address. When it passes, the proxy configuration is not applied: check the
``reverseProxyIP`` value. Remove the rule after the test.
