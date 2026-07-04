..  include:: Includes.txt

==========
Statistics
==========

The extension records firewall events (blocked requests, bans, rate limit
hits, errors) in the database table ``tx_firewall_event`` and shows them in
the backend module: how many attackers were blocked today, a chart over
time, and the most triggered rules and paths.

Event logging is enabled by default and can be tuned in the extension
configuration: which event types to log, how long to keep entries, and
whether IP addresses are anonymized. The console command
``firewall:eventlog:prune`` deletes old entries.

This page will be extended with the full settings reference and the privacy
model.
