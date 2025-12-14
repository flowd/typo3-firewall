..  include:: Includes.txt

====================
Phirewall
====================

This extension uses the open-source package `phirewall` as its technical foundation. The full documentation and all features can be found at:

https://github.com/flowd/phirewall

Core configuration
------------------

Phirewall itself is configured via a PHP configuration file::

   config/system/phirewall.php

This file controls the global behaviour of Phirewall (rules, backends, etc.).

Key notes
---------

- Configuration is done via PHP array files.
- The pattern logic is identical to the standalone Phirewall package.
- Advanced features such as rate limiting, dynamic rules, etc. are also available.
