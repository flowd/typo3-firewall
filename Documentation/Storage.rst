..  include:: Includes.txt

=======
Storage
=======

Rate limiting and bans need a store that persists counters between requests.
The store is the first argument of the ``Config`` object in your
configuration file.

Recommended stores:

- ``PdoCache``: reuses the TYPO3 database connection, works everywhere
- ``ApcuCache``: fastest option on a single-server setup.
- ``RedisCache``: recommended for multi-server setups

The TYPO3 caching framework cannot be used as a store: it does not implement
PSR-16 and does not offer the atomic counters the firewall needs.

This page will be extended with configuration examples for every store.
