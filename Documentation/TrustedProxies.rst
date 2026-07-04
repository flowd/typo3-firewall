..  include:: Includes.txt

===============
Trusted proxies
===============

Rules that work with the client IP need the real visitor address, not the
address of a reverse proxy or CDN in front of your website.

The extension resolves the client IP through
``GeneralUtility::getIndpEnv('REMOTE_ADDR')`` by default. This applies the
``reverseProxyIP`` settings of your TYPO3 installation, so a correctly
configured TYPO3 also gives the firewall the correct client IP.

This page will be extended with typical proxy setups and troubleshooting.
