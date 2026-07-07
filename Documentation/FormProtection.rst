..  include:: Includes.txt

=====================
Form flood protection
=====================

Ban clients that submit a form faster than a real visitor plausibly would.
The extension ships a finisher for the TYPO3 Form Framework (``EXT:form``)
that reports every submission of a form to the firewall. An allow2ban rule
counts the submissions per client and bans the client once it crosses the
threshold; the :doc:`middleware <Middleware>` then rejects further requests
early, before TYPO3 boots.

The finisher counts every *valid* submission, not only suspicious ones:
finishers run after the form validation, so rejected submissions are not
counted. Unlike a honeypot or CAPTCHA, which target bots, it also stops
real visitors who hammer a form. Use it alongside those measures, not
instead of them.

..  warning::

    An allow2ban ban blocks the client's IP address for the *whole site*, not
    just the form. Visitors behind a shared IP (company NAT, campus
    networks) count against the same limit and would be locked out
    together. Keep the threshold generous enough for that case.

..  note::

    Requirements: ``typo3/cms-form`` must be installed, and the firewall
    needs a persistent store (see :doc:`Storage`). With the default
    ``InMemoryCache`` the counters reset on every request and the rule never
    triggers; the extension logs a warning in that case.

Enable it
=========

#.  In :guilabel:`Admin Tools > Settings > Extension Configuration >
    firewall`, enable :guilabel:`form flood protection`. This registers an
    allow2ban rule named ``form-flood`` with the configured threshold
    (default 5 submissions), period (default 60 seconds), and ban duration
    (default 1 hour).

#.  In the form editor, add the :guilabel:`Firewall: flood protection`
    finisher to each form you want to protect.

Both steps are needed: without the rule, reported submissions are ignored;
without the finisher, nothing reports. The client is identified by IP
address, resolved with the same trusted-proxy handling as the rest of the
firewall (see :doc:`TrustedProxies`).

Replace the default rule
========================

For full control over the rule, define ``form-flood`` in
:file:`config/system/phirewall.php` yourself. A rule from the configuration
file always wins over the generated default:

..  code-block:: php

    $config->allow2ban->add(
        'form-flood',
        threshold: 3,
        period: 120,
        banSeconds: 7200,
        // Fed by the finisher; the rule never matches a request on its own.
        filter: static fn(): bool => false,
    );

Give a form its own counter
===========================

By default every form using the finisher reports to the same ``form-flood``
rule, so their submissions share one counter per client: a visitor filling
in several different forms counts towards a single limit, and the resulting
ban applies site-wide. To count a form on its own, point its finisher at a
separate allow2ban rule.

In the form editor, the :guilabel:`Firewall: flood protection` finisher has a
:guilabel:`Allow2ban rule identifier` field. Enter a name other than
``form-flood`` (for example ``contact-form-flood``) to give that form its own
counter. The rule must exist, so define it in
:file:`config/system/phirewall.php` (the extension configuration only
registers the default ``form-flood`` rule):

..  code-block:: php

    $config->allow2ban->add(
        'contact-form-flood',
        threshold: 3,
        period: 120,
        banSeconds: 7200,
        // Fed by the finisher; the rule never matches a request on its own.
        filter: static fn(): bool => false,
    );

A submission reported to a rule name that is not defined is ignored, so a
typo in the field silently disables protection for that form; double-check
the name matches the rule in ``phirewall.php``.

Change the rule from code
-------------------------

Before a submission is reported, the finisher dispatches the
:php:`Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered` event with
the rule identifier the finisher resolved (the option above, or the default).
A listener can change it, for example to derive the rule from the form, or
set an empty identifier to skip the submission:

..  code-block:: php

    use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;

    final class UseStricterContactFormRule
    {
        public function __invoke(FloodProtectionFinisherTriggered $event): void
        {
            $event->ruleIdentifier = 'contact-form-flood';
        }
    }

Register the class as an event listener in the :file:`Services.yaml` of
your site package. The rule it points to must be defined in
:file:`config/system/phirewall.php`.
