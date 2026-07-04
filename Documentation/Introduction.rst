..  include:: Includes.txt

============
Introduction
============

What does the extension do?
===========================

The Firewall extension adds a web application firewall to your TYPO3 website.
It inspects every frontend request before TYPO3 processes it and can:

- Block requests from specific IP addresses or IP ranges
- Block requests for suspicious paths, headers, or patterns
- Limit how often a client can call certain pages (rate limiting)
- Ban clients temporarily after repeated abuse (like Fail2Ban)
- Record firewall events and show statistics in the backend

Editors and administrators manage static block patterns directly in the
TYPO3 backend module. Changes take effect immediately, without a deployment.

Relation to phirewall
=====================

The firewall engine is the open-source package
`flowd/phirewall <https://github.com/flowd/phirewall>`__. The extension wires
it into TYPO3: it registers the request middleware, loads your configuration
file, resolves the client IP through TYPO3, and adds the backend module
and the event log.

This documentation covers everything TYPO3-specific. All engine features
(rule types, stores, advanced options) are documented at
https://phirewall.de/ and are used exactly the same way inside TYPO3.

Where things live
=================

- Firewall configuration: ``config/system/phirewall.php`` (see :doc:`Configuration`)
- Backend managed block patterns: ``config/system/phirewall.patterns.json`` (see :doc:`BackendModule`)
- Recorded firewall events: database table ``tx_firewall_event`` (see :doc:`Statistics`)
