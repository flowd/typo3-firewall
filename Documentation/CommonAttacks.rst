..  include:: Includes.txt

==============
Common attacks
==============

Problem-first recipes: what to do when a specific kind of unwanted traffic
hits your site. Each section names the right tool and links to the chapter
with the details.

..  tip::

    If a CDN/WAF (such as Cloudflare) runs in front of your site, filter
    there first: it stops unwanted traffic before it reaches the
    application. The extension complements that with TYPO3-aware rules, and
    is your main line of defence when there is no edge layer.

..  contents::
    :local:

Spam and flooding on a contact form
===================================

Form spam is almost always automated, so hardening the form itself beats
chasing the constantly rotating IP addresses. In forms built with the TYPO3
Form Framework, start with the built-in **honeypot** (and a CAPTCHA where
available); other form extensions ship equivalent protections. Beyond that:

-   For forms built with the TYPO3 Form Framework, add the
    :guilabel:`Firewall: flood protection` finisher. It reports every
    submission to the firewall and bans a client that submits faster than a
    configured threshold, catching both bots and real visitors hammering the
    form. This is the extension's dedicated answer to form flooding, see
    :doc:`FormProtection`.

-   A single IP address or network keeps abusing the form: add a pattern of
    kind ``ip`` or ``cidr`` in the :doc:`backend module <BackendModule>`,
    with an ``expiresAt`` a few days out so it cleans itself up.

-   Cap how often the form can be submitted with a throttle in
    :file:`config/system/phirewall.php`, scoped to the page that holds the
    form so it cannot affect the rest of the site:

    ..  code-block:: php

        $config->throttles->add(
            name: 'contact-form-flood',
            limit: 3,
            period: 600,
            key: function (\Psr\Http\Message\ServerRequestInterface $request): ?string {
                // Only count POST submissions to the contact page.
                if ($request->getMethod() !== 'POST'
                    || !str_starts_with($request->getUri()->getPath(), '/contact')) {
                    return null; // the rule does not apply to other requests
                }
                // getIndpEnv() applies the reverseProxyIP settings, so the
                // throttle keys on the real client IP behind a proxy or CDN.
                $clientIp = \TYPO3\CMS\Core\Utility\GeneralUtility::getIndpEnv('REMOTE_ADDR');
                return is_string($clientIp) && $clientIp !== '' ? $clientIp : null;
            },
        );

Throttles need a persistent store, see :doc:`Storage`.

Brute-force login attempts
==========================

..  note::

    The recipes below cover **frontend** logins (felogin or a custom login)
    only. The firewall and its aspect run as frontend middlewares, so
    brute-force attempts against the backend login (``/typo3``) never reach
    them. TYPO3 rate limits backend logins itself; the :doc:`FAQ <Faq>`
    explains why the backend is not protected and what to do instead.

The firewall runs before TYPO3, so on its own it cannot tell a failed
login from a normal request. Two approaches:

-   **Count login posts.** Ban clients that post to the login page again
    and again, no code needed: see the allow2ban recipe in
    :doc:`Examples`. Simple, but it counts successful and failed logins
    alike, so the threshold must stay generous.

-   **Report failed logins.** Precise, in two steps. First define the rule
    in :file:`config/system/phirewall.php`:

    ..  code-block:: php

        $config->fail2ban->add(
            'login-failures',
            threshold: 5,
            period: 300,
            ban: 3600,
            // Failures are reported explicitly, the filter never matches on
            // its own.
            filter: static fn(): bool => false,
        );

    Then report each failed login, for example from a listener on TYPO3's
    failed-login event, through the firewall Context aspect:

    ..  code-block:: php

        use TYPO3\CMS\Core\Context\Context;
        use TYPO3\CMS\Core\Utility\GeneralUtility;

        GeneralUtility::makeInstance(Context::class)
            ->getAspect('firewall')
            ->recordFailure('login-failures');

    The ``firewall`` aspect is registered automatically in frontend
    requests, see :doc:`Middleware`. Only reported failures count, so
    legitimate users are never locked out by successful logins.

SQL injection and other request payload attacks
===============================================

Attacks that hide in the request content (query string, body, headers) need
a rule engine rather than a block list. Install the OWASP Core Rule Set
preset package and pick a paranoia level, see :doc:`Presets`.

A crawler is slowing down the site
==================================

The right response depends on which crawler it is; the ``User-Agent``
header in your access log tells you.

-   **Search engines and AI search bots** (Googlebot, Bingbot, OpenAI's
    ``OAI-SearchBot``, Anthropic's ``Claude-SearchBot``) should generally
    not be blocked: they are how people find and get referred to your
    site. To ease the load instead: Bing and Yandex honour a ``Crawl-delay``
    in :file:`robots.txt`; Googlebot ignores it, but treats repeated
    ``429``/``503`` responses as an overload signal and temporarily lowers
    its crawl rate, so a throttle that answers with ``429`` is a valid way
    to slow it down.

-   **AI training crawlers** (``GPTBot``, ``ClaudeBot``, ``CCBot``) honour
    :file:`robots.txt`, which is the appropriate place to opt out:

    ..  code-block:: text

        User-agent: GPTBot
        Disallow: /

        User-agent: ClaudeBot
        Disallow: /

        User-agent: CCBot
        Disallow: /

    Blocking these controls whether your content is used for AI training;
    it does not affect whether AI tools can find or cite your site.

-   **SEO crawlers** (AhrefsBot, SemrushBot, MJ12bot, DotBot) can be rate
    limited or blocked with the bot control preset, see :doc:`Presets`, or
    opted out via :file:`robots.txt`.

..  note::

    Blocking by User-Agent only works for crawlers that identify
    themselves honestly. Stealth crawlers that
    `spoof a browser User-Agent <https://blog.cloudflare.com/perplexity-is-using-stealth-undeclared-crawlers-to-evade-website-no-crawl-directives/>`__
    need behaviour-based rules (throttles, fail2ban) or edge defences.

Traffic from specific countries
===============================

Geo-blocking is best handled at the edge (CDN/WAF). Inside TYPO3 there is
no reliable country signal, hand-maintained per-country IP ranges go stale
fast, and even done well it is blunt: it blocks real visitors and VPN
users while attackers switch countries. Filtering on behaviour rather than
origin (scanner paths, throttles, fail2ban) catches malicious traffic
regardless of where it comes from. If geo-blocking is a hard compliance
requirement, it belongs at the hosting or CDN layer.

Which rule blocked a visitor?
=============================

Open the backend module: :guilabel:`Blocked keys` lists the active
fail2ban/allow2ban bans grouped by rule, :guilabel:`Patterns` the static
blocks. Remove the matching entry to unblock the visitor immediately. The
:doc:`event log <Statistics>` shows which rule matched historically.

On development or staging systems, diagnostic response headers name the
matching rule on every blocked response:

..  code-block:: php

    $config->enableResponseHeaders();
    $config->enableOwaspDiagnosticsHeader(); // adds the OWASP rule ID

A blocked response then carries ``X-Phirewall`` (the block type) and
``X-Phirewall-Matched`` (the rule name).

..  warning::

    Enable diagnostic headers only in development or staging. In
    production they reveal your rule set to attackers.
