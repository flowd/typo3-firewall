..  include:: Includes.txt

====================
Backend
====================

The TYPO3 backend provides a dedicated module for managing block patterns easily.

- Create, edit, and delete patterns
- Select the pattern type (e.g. IP, path, header)
- Specify value, target (e.g. header name), and expiration date
- Overview of all active patterns
- Immediate activation after saving

Patterns are stored in the file ``config/system/phirewall.patterns.php`` and are used directly by the firewall.
