..  include:: Includes.txt

==============
Backend module
==============

The extension adds a backend module under **System** >
**Firewall**. It is available to administrators only.

The module has three views. Switch between them with the **View**
dropdown in the module's doc-header:

- **Patterns** manages the static block patterns.
- **Blocked keys** lists the clients that rules have banned automatically.
- **Statistics** shows how much traffic the firewall blocked over time.

Patterns
========

This view manages the static block patterns. The extension always adds them
to the firewall as the blocklist rule ``typo3-blocklist``, so they take
effect even when no configuration file exists (see :doc:`Configuration`).
Patterns are stored in the file ``config/system/phirewall.patterns.json``
(classic installation: ``typo3conf/system/phirewall.patterns.json``).

Every change takes effect on the next request. No deployment and no cache
flush are needed.

The pattern list
----------------

The **Active Patterns** list shows one row per pattern with its kind,
value, target, expiry date, creation date, and last change. A pattern that
has passed its expiry date is highlighted and no longer blocks requests,
until you remove it or run a prune (see below).

Add and edit patterns
----------------------

The form next to the list creates a new pattern. Pick a kind, enter the
value, and save. To change a pattern, open it from the list, edit the
fields, and save. The form checks the value before it stores the pattern
and shows a clear message when something is wrong, for example an invalid
IP address or a broken regular expression.

Pattern kinds
-------------

A pattern's kind decides what part of the request it compares against.

``ip``
    Blocks one exact client IP address, for example ``203.0.113.10``.

``cidr``
    Blocks a whole IP range in CIDR notation, for example
    ``203.0.113.0/24``.

``path_exact``
    Blocks requests whose path is exactly this value, for example
    ``/old-login``.

``path_prefix``
    Blocks requests whose path starts with this value, for example
    ``/wp-admin``.

``path_regex``
    Blocks requests whose path matches this regular expression, for example
    ``#^/(wp-admin|xmlrpc\.php)#``.

``header_exact``
    Blocks requests where a header has exactly this value. Put the header
    name in the target field, for example target ``User-Agent`` and value
    ``BadBot/1.0``.

``header_regex``
    Blocks requests where a header matches this regular expression. Put the
    header name in the target field, for example target ``User-Agent`` and
    value ``#(sqlmap|nikto)#i``.

``request_regex``
    Blocks requests where the regular expression matches a combined string
    of the path, the query string, and the request headers, for example
    ``#(union\s+select|<script)#i``.

The target field is only used by the two header kinds. For every other kind
you can leave it empty.

Expiry and prune
----------------

The expiry date is optional. When set, it must lie in the future. An expired
pattern stops blocking at once, but its row stays in the list so you can see
it. The **Prune** button deletes all expired patterns in one step.

Integrity check
---------------

The view checks the pattern file on every visit. When the file is broken,
for example because it holds invalid data or a pattern with an unknown kind,
a warning banner appears. The firewall silently skips the affected entries
during request handling, so the banner is your signal to open the
patterns file and fix or remove them.

Blocked keys
============

This view lists the keys that ``fail2ban`` and ``allow2ban`` rules have
banned automatically. A key is usually a client IP address. The bans are
read live from the store that your configuration uses (see :doc:`Storage`),
so the view is empty when you use the ``InMemoryCache``, which keeps no state
between requests.

Bans are grouped by the rule that created them. Each group carries a badge
that shows the rule type, ``fail2ban`` or ``allow2ban``. Inside a group every
ban shows the key, the remaining time, and the exact time the ban ends. The
bans with the least time left are listed first. Use the search field to find
a single key across all groups.

The **Unban** button removes a single ban after a confirmation
dialog and lets the key through again right away. When the behavior that
triggered the ban continues, the rule bans the key again on the next
matching request.

Blocklist matches do not appear here. A blocklist rule answers each matching
request with a 403 response on the spot and keeps no ban, so there is nothing
to list. To see blocklist activity, use the event log and the
:doc:`Statistics` view.

Statistics
==========

This view answers one question: how much unwanted traffic the firewall
blocked. It shows the number of attackers blocked today, a chart over time,
and the rules and paths that triggered most often. For the full description
of the recorded data, the privacy model, and the extension settings, see
:doc:`Statistics`.
