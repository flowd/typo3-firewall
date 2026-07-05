..  include:: Includes.txt

===
FAQ
===

Short answers to questions that come up when running the firewall in TYPO3.

For questions about the firewall engine itself (rule evaluation, stores,
advanced features) see the
`phirewall FAQ <https://phirewall.de/faq.html>`__.

Why is the TYPO3 backend not protected?
=======================================

The firewall runs as a frontend middleware. It covers the TYPO3 frontend
only, not ``/typo3``, the install tool, or files that the web server delivers
directly (see :doc:`Middleware`). Protect the backend at the web server or
network level, for example with an IP allow list for ``/typo3``. TYPO3 also
brings its own rate limiting for backend login attempts.

How does the firewall see the real client IP behind a proxy?
=============================================================

The extension resolves the client IP through
``GeneralUtility::getIndpEnv('REMOTE_ADDR')``, which applies the
``reverseProxyIP`` settings of your TYPO3 installation. Configure those
settings once and both TYPO3 and the firewall see the real visitor address
(see :doc:`TrustedProxies`).

Can I use the TYPO3 caching framework as a store?
=================================================

No. The store must implement PSR-16 and offer atomic counters for rate
limiting and bans. The TYPO3 caching framework does neither, so counters
would be lost or wrong. Use one of the stores in :doc:`Storage`, for
example ``ApcuCache`` on a single server.

Should I commit phirewall.patterns.json?
========================================

Usually not. The file holds the block patterns that editors manage in the
backend module at runtime, so it is data, not code. When you deploy the file
from Git, a deployment overwrites the changes made on the live site. Exclude
it from deployment (for example through ``.gitignore``) unless you never
touch the patterns in the backend and manage them only in the file.

What happens if the configuration file has an error?
====================================================

The extension falls back to the default configuration: the ``InMemoryCache``
store and only the backend block patterns. The website keeps working. A file
that does not return a closure, or whose closure does not return a ``Config``
object, logs a warning. A file that fails, for example with a syntax error or
an exception, logs an error. Check the TYPO3 log after changing the file, and
test changes on a staging system first.

Why is the blocked keys view empty?
===================================

The view lists the bans that ``fail2ban`` and ``allow2ban`` rules created and
that are still active. It is empty when you use the ``InMemoryCache``, which
keeps no state between requests, when your configuration has no fail2ban or
allow2ban rules, or when no ban is active right now. When the
``InMemoryCache`` is active, the view shows a warning, and the firewall
logs one when counter rules are registered on it. Blocklist matches never
appear here, because they answer each request with a 403 and keep no ban.

Why is the statistics view empty?
=================================

Most often event logging is switched off. When ``eventLogEnabled`` is off the
view shows a hint and stays empty. Otherwise there may be no events yet in the
selected time range, or the event types you look for are not in the
``eventLogTypes`` setting (see :doc:`Statistics`).

Does the extension work without Composer?
=========================================

Yes. Install the package from the TYPO3 Extension Repository. The TER package
bundles the phirewall library, the three preset packages, and
``psr/simple-cache``, so nothing else is needed (see :doc:`Installation`).

What does the firewall cost per request?
========================================

Little. The middleware runs early, before TYPO3 resolves the site or the
page, so a blocked request is answered at once and never reaches the CMS. For
an allowed request the cost is evaluating your rules. Counter rules (throttle,
fail2ban, allow2ban, track) each do one store lookup, so a fast store keeps
the overhead low on busy sites. Event logging adds one database insert per
recorded event, not per request, and the high-volume event types are off by
default.

How do I disable the firewall in an emergency?
==============================================

Rename or empty the configuration file. The extension then falls back to the
default configuration, and only the backend block patterns stay active. To
drop those too, remove the patterns in the backend module. Inside the file
you can also call ``$config->disable()`` to let every request pass without
any check.

What if I locked myself out?
============================

The firewall never runs in the backend, so a rule can block your frontend
access but never ``/typo3``. Open the backend module and remove the pattern
in the **Patterns** view, or lift the ban in the
**Blocked keys** view. When a rule in the configuration file is the
cause, edit or rename that file (see :doc:`BackendModule`).

What about the event log and GDPR?
==================================

The event log is built to hold as little personal data as possible. The
client key, usually the IP address, is stored only as a SHA-256 hash. A
readable address is kept only for real IP addresses and, by default, only in
shortened form. Entries are deleted after the retention period. The log also
stores the request path, method, host, and user agent. Review this against
your privacy policy, keep IP anonymization on when you do not need full
addresses, and set a retention that fits your needs (see :doc:`Statistics`).

Why are bans gone after the upgrade to 0.4?
===========================================

Version 0.4 updates the firewall engine from phirewall 0.3 to 0.7. Along the
way the engine changed its internal cache key format. Active bans and running
counters are forgotten once when you deploy the upgrade, then rebuild with the
next matching requests. This reset
happens only once (see :doc:`Installation`).
