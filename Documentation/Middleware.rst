..  include:: Includes.txt

==========
Middleware
==========

The extension registers the firewall as a PSR-15 middleware in the TYPO3
frontend request stack. It runs early, before TYPO3 resolves the site and
page, so blocked requests cost almost no resources.

The middleware protects the website frontend only. The TYPO3 backend
(``/typo3``) and the install tool are not covered.

This page will be extended with details on the middleware position and how
to protect other entry points.
