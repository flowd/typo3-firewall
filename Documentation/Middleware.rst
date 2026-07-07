..  include:: Includes.txt

==========
Middleware
==========

The extension registers the firewall as a PSR-15 middleware in the TYPO3
frontend request stack.

Position in the request stack
=============================

The middleware runs early: after ``typo3/cms-frontend/timetracker`` and
before ``typo3/cms-core/normalized-params-attribute``. Two consequences
follow from this position:

- Blocked requests are cheap. The firewall answers before TYPO3 resolves
  the site, the page, or any content.
- The firewall sees the raw request. TYPO3's normalized parameters and site
  handling have not run yet. That is why the extension resolves the client
  IP itself (see :doc:`TrustedProxies`).

What is protected, and what is not
==================================

The middleware covers every request that reaches the TYPO3 frontend,
including page requests, frontend login forms, and frontend APIs.

Not covered:

- The TYPO3 backend (``/typo3``) and its login
- The install tool (``/typo3/install.php``)
- Files that the web server delivers directly, for example everything under
  ``fileadmin`` or ``_assets``

Protect these entry points at the web server or network level, for example
with IP allow lists for ``/typo3``. TYPO3 itself brings rate limiting for
backend login attempts.

..  warning::

    If you register the firewall middleware in the backend stack yourself,
    a rule that matches too much can lock you out of the backend, including
    the module you would use to remove the ban. Test rules in the frontend
    first.

Disable the firewall temporarily
================================

Return a configuration without rules, or rename the configuration file. The
extension then falls back to the default configuration, and only the block
patterns from the :doc:`backend module <BackendModule>` stay active. To
disable those too, remove the patterns in the backend module.

Read the firewall decision from PHP code
========================================

A second middleware ``flowd/typo3-firewall-aspect`` exposes the firewall
decision through the TYPO3 Context API as the ``firewall`` aspect. Like the
firewall itself it runs in the frontend stack only, so the aspect is
available in frontend requests and not in the backend. Application code can
read the decision through the aspect:

..  code-block:: php

    use TYPO3\CMS\Core\Context\Context;
    use TYPO3\CMS\Core\Utility\GeneralUtility;

    $firewallAspect = GeneralUtility::makeInstance(Context::class)->getAspect('firewall');

    // The FirewallResult of the current request:
    $firewallResult = $firewallAspect->get('result');

    // Report an application-level failure, for example a failed login,
    // to a fail2ban rule defined in phirewall.php:
    $firewallAspect->recordFailure('login-failures');

    // Report a hit to an allow2ban rule, for example an expensive
    // operation the firewall cannot see from the request alone:
    $firewallAspect->recordHit('expensive-operation');

``recordFailure()`` and ``recordHit()`` count against the client IP by
default; the firewall resolves it with your trusted-proxy settings after
the handler has finished. Pass a key as second argument only when the rule
should count something the firewall cannot derive from the request itself.
Signals reported to a rule name that is not configured are ignored, so
calling code does not need to check the configuration first.

The extension ships a `phpstan <https://phpstan.org/>`__ configuration that
maps ``getAspect('firewall')`` to the :php:`FirewallAspect` class. Projects
using ``phpstan/extension-installer`` pick it up automatically.

..  note::

    The aspect is only registered when the firewall middleware has run for
    the current request. Otherwise ``getAspect('firewall')`` throws an
    ``AspectNotFoundException``.

If you do not want the aspect registered at all, disable the middleware in
the :file:`Configuration/RequestMiddlewares.php` of your site package:

..  code-block:: php

    <?php

    return [
        'frontend' => [
            'flowd/typo3-firewall-aspect' => [
                'disabled' => true,
            ],
        ],
    ];
