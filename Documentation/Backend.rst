..  include:: Includes.txt

====================
Backend
====================

The TYPO3 backend provides a dedicated module for managing the firewall.
Switch between the two views via the dropdown in the module's doc-header.

Patterns
========

Manage the static block list used by the firewall middleware.

- Create, edit, and delete patterns
- Select the pattern type (e.g. IP, path, header)
- Specify value, target (e.g. header name), and expiration date
- Overview of all active patterns
- Immediate activation after saving

Patterns are stored in the file ``config/system/phirewall.patterns.json`` and
are used directly by the firewall.

Blocked keys
============

Manage keys (e.g. IP addresses) that the firewall has banned automatically
through ``fail2ban`` or ``allow2ban`` rules.

- List all currently active bans, grouped by rule
- Each entry shows the banned key, the rule type (``fail2ban`` or
  ``allow2ban``), and the time the ban expires
- Remove a single ban to immediately allow the key again

Bans are read from and written to the cache store configured for the
firewall (see :doc:`Phirewall`). Removing a ban here only clears the entry
for the selected rule; if the underlying condition that triggered the ban
still applies, the key may be banned again on the next matching request.
