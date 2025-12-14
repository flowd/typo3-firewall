..  include:: Includes.txt

====================
Features
====================

Key features of the Firewall extension:

- Integration of the Phirewall package (see :doc:`Phirewall`)
- Management of static block patterns in the backend
- Support for various pattern types (IP, CIDR, path, header, user agent, regex)
- Expiration date for patterns (expiresAt)

Configuration overview
----------------------

- Core Phirewall configuration: ``config/system/phirewall.php``
- Static custom patterns managed by this extension: ``config/system/phirewall.patterns.php``
