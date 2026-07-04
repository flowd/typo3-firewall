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
