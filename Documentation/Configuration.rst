..  include:: Includes.txt

=============
Configuration
=============

The firewall is configured in one PHP file:

``config/system/phirewall.php``

The file returns a closure. The closure receives the TYPO3 event dispatcher
and returns a configured ``Flowd\Phirewall\Config`` object. See
:doc:`QuickStart` for a minimal example and the
`phirewall documentation <https://phirewall.de/>`__ for all rule types and
options.

When the file is missing, the firewall falls back to a safe default
configuration. A broken file logs the problem on top. The block patterns
managed in the :doc:`backend module <BackendModule>` are always active.

This page will be extended with the full configuration reference.
