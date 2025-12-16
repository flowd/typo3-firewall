..  include:: Includes.txt

====================
Firewall Extension
====================

The TYPO3 Firewall extension provides two main possibilities:

1. Use all features of the Phirewall package
--------------------------------------------

This extension integrates the powerful open-source package `phirewall` and makes its features available in the TYPO3 context. This includes:

- Protection against brute-force and other attacks
- Flexible pattern and rule definitions (IP, path, header, user agent, etc.)
- Support for blacklists, whitelists, rate limiting, and more
- Central configuration via PHP array files

**Configuration of Phirewall**
Phirewall itself is configured in the core configuration file::

   config/system/phirewall.php

All details and advanced features can be found in the official Phirewall documentation: https://github.com/flowd/phirewall

2. Manage static block patterns in the TYPO3 backend
----------------------------------------------------

Via the TYPO3 backend, editors and administrators can create, edit, and delete custom block patterns. These patterns become active immediately and extend the Phirewall configuration.

- Easy management of IPs, paths, headers, etc. via the backend module
- Overview and management of all active patterns
- Support for expiration date (expiresAt) and various pattern types
- Immediate enforcement of rules without deployment

Further information
-------------------

* Patterns are stored in the file ``config/system/phirewall.patterns.php``.
* The extension follows TYPO3 core conventions and can be extended easily.

..  menu::
    :maxdepth: 1
    :titlesonly:

    Features <Features>
    Backend <Backend>
    Phirewall <Phirewall>
