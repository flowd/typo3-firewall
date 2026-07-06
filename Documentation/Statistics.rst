..  include:: Includes.txt

==========
Statistics
==========

The extension records what the firewall does and shows it in the
**Statistics** view of the :doc:`backend module <BackendModule>`.
This lets you see how much unwanted traffic your website receives and which
rules and paths are hit most.

The event log
=============

Every firewall action is written as one row to the database table
``tx_firewall_event``. A row holds the event type, the rule name, the ban
type for ban events, the client key (see the privacy section below), the
request host, path, and method, the user agent, rule numbers such as the
threshold and the counter, for errors the exception class and message, and
the time. It never stores a page, a session, or content. The recorded event
types are:

``blocklist_matched``
    A blocklist rule answered a request with a 403 response.

``throttle_exceeded``
    A client sent more requests than a rate limit allows.

``fail2ban_banned``
    A fail2ban rule banned a client after repeated abuse.

``allow2ban_banned``
    An allow2ban rule banned a client for too many requests.

``safelist_matched``
    A safelist rule let a request through without further checks.

``track_hit``
    A track rule counted a request without blocking it.

``firewall_error``
    The firewall hit an internal error, for example when the store was
    unreachable.

The first four types count as a blocked attacker. They feed the numbers, the
chart, and the top lists in the statistics view. The ``safelist_matched`` and
``track_hit`` types are high volume and switched off by default, because they
fire on normal traffic and would fill the table quickly.

Settings
========

The extension configuration controls what is logged and for how long. Open
it under **Admin Tools** > **Settings** >
**Extension Configuration** and select ``firewall``.

``eventLogEnabled`` (default: on)
    Turns the event log on or off. When off, nothing is recorded and the
    statistics view stays empty.

``eventLogTypes`` (default: ``blocklist_matched``, ``throttle_exceeded``, ``fail2ban_banned``, ``allow2ban_banned``, ``firewall_error``)
    A comma-separated list of the event types to record. Add
    ``safelist_matched`` or ``track_hit`` only when you need them, and expect
    many more rows.

``eventLogRetentionDays`` (default: 30)
    How many days to keep entries. The prune command uses this value.

``eventLogAnonymizeIp`` (default: on)
    Stores client IP addresses in shortened form. The last part of the
    address is dropped, so a single visitor can no longer be identified.

Privacy and retention
======================

The event log is built to hold as little personal data as possible.

- The key of a client, usually its IP address, is stored only as a SHA-256
  hash. The hash lets the view count distinct clients without storing the
  raw key.
- A readable address is kept in a separate field for the backend view, but
  only for real IP addresses and, with ``eventLogAnonymizeIp`` on, only in
  shortened form. Keys that are not IP addresses are never shown in readable
  form.
- Entries are deleted after the retention period. The console command
  removes the old rows:

  ..  code-block:: bash

      vendor/bin/typo3 firewall:eventlog:prune

  The command deletes entries older than the configured retention. Pass
  ``--days`` to override it once, for example ``--days 7``. Register the
  command as a scheduler task or a cron job so old entries are removed
  regularly.

How to read the statistics view
===============================

When event logging is off, the view shows a hint and stays empty. Otherwise
it shows:

- Two large numbers at the top: **Attackers blocked today**, the count of
  distinct clients blocked since midnight, and **Blocked requests**, the
  total for the selected time range.
- A time range switch with three options: the last 24 hours, 7 days, or 30
  days. The 24-hour range groups the data by hour, the other two by day.
- A **Blocked requests over time** chart. Each bar is stacked and split by
  event type, so you see at a glance whether blocklists, rate limits, or bans
  caused the traffic. Every type keeps the same color across ranges, and a
  legend below the chart names each color with its count.
- A **Recent blocked requests** table with the last 20 blocking events in
  the selected range. Each row shows the time, the event type in the same
  color as the chart, the rule that fired, the request method and path, and
  the client. This answers which rule blocked a specific request.
- A **Top rules** list with the five rules that blocked the most requests,
  and a **Top blocked paths** list with the five paths that attackers
  targeted most.
- An **Events by type** list with the count per event type in the range.

Dashboard widgets
==================

The extension ships two widgets for the TYPO3 dashboard. They need the
``typo3/cms-dashboard`` package (see :doc:`Installation`) and read from the
same event log.

**Firewall: Blocked today**
    A single number: the distinct attackers blocked since midnight.

**Firewall: Blocked requests**
    A bar chart of the blocked requests per day over the last seven days.

Statistics, blocked keys, and patterns
=======================================

The backend module shows firewall data in three ways. It helps to keep them
apart:

- **Statistics** is the history. It tells you what happened over time, even
  for events that are long over.
- **Blocked keys** is the present. It lists the bans that are active right
  now and lets you lift them (see :doc:`BackendModule`).
- **Patterns** are the static rules you manage by hand. They do not depend on
  past traffic (see :doc:`BackendModule`).
