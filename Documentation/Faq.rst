..  include:: Includes.txt

====================
FAQ
====================

..  tip::

    If you have a CDN/WAF (such as Cloudflare) in front of your site, filtering
    there is most effective, as it stops unwanted traffic before it reaches the
    application. This extension complements that with TYPO3-aware rules at the
    application level, and is your main line of defence when there is no edge
    layer.

..  contents::
    :local:

How do I stop spam and flooding on a contact form?
==================================================

Form flooding is almost always automated – bots, not individual people – so
hardening the form itself is far more effective than chasing individual IP
addresses, which rotate constantly. In forms built with the TYPO3 Form Framework
(`ext:form`), the most reliable fix lives in the form editor: the built-in
**honeypot** (and a **CAPTCHA**, where available) stops the bulk of automated
submissions with no impact on genuine visitors. Forms built with another
extension (e.g. Powermail) offer equivalent spam protection of their own.
Beyond that:

..  tabs::

    ..  group-tab:: Backend Module

        If a single IP address or network is responsible for repeated abuse, add
        a pattern of kind `ip` (a single address) or `cidr` (a whole network
        range), with an `expiresAt` a few days out so it cleans itself up.
        Capping how often the form can be submitted (a true rate limit) is more
        robust, but is configured at file level in
        `config/system/phirewall.php`.

    ..  group-tab:: config/system/phirewall.php

        Add a throttle as a ceiling, scoped to the contact page so it cannot
        affect the rest of the site:

        ..  code-block:: php

            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\ApcuCache;
            use Psr\EventDispatcher\EventDispatcherInterface;
            use Psr\Http\Message\ServerRequestInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new ApcuCache(), $eventDispatcher);
                $config->throttles->add(
                    name: 'contact-form-flood',
                    limit: 3,
                    period: 600,
                    key: function (ServerRequestInterface $request): ?string {
                        // Only count POST submissions to the contact page.
                        if ($request->getMethod() !== 'POST'
                            || !str_starts_with($request->getUri()->getPath(), '/contact')) {
                            return null; // rule does not apply to other requests
                        }
                        return $request->getServerParams()['REMOTE_ADDR'] ?? null;
                    },
                );
                return $config;
            };

How do I stop brute-force login attempts?
=========================================

The firewall runs before TYPO3, so on its own it cannot tell a failed login
from a normal request. Brute-force protection takes two steps: define a
Fail2Ban rule, and report each failed login to the firewall. It then counts the
failures per IP and bans the address once the threshold is reached.

1. Define the rule in `config/system/phirewall.php`:

..  code-block:: php

    <?php
    use Flowd\Phirewall\Config;
    use Flowd\Phirewall\KeyExtractors;
    use Flowd\Phirewall\Store\ApcuCache;
    use Psr\EventDispatcher\EventDispatcherInterface;

    return function (EventDispatcherInterface $eventDispatcher): Config {
        $config = new Config(new ApcuCache(), $eventDispatcher);
        $config->fail2ban->add(
            'login-failures',
            threshold: 5,
            period: 300,
            ban: 3600,
            // Failures are reported explicitly (step 2), so the filter never
            // matches on the request and the key is unused here.
            filter: fn(): bool => false,
            key: KeyExtractors::ip(),
        );
        return $config;
    };

2. Report a failed login from your login flow (for example a listener on
   TYPO3's failed-login event), via the firewall Context aspect:

..  code-block:: php

    use TYPO3\CMS\Core\Context\Context;
    use TYPO3\CMS\Core\Utility\GeneralUtility;

    GeneralUtility::makeInstance(Context::class)
        ->getAspect('firewall')
        ->recordFailure('login-failures', $clientIp);

This requires the opt-in `flowd/typo3-firewall-aspect` middleware to be enabled,
which registers the `firewall` aspect. After the response is sent, the firewall
increments the counter and bans the IP once five failures occur within five
minutes. Only reported failures count, so legitimate editors are never locked
out. Full guide:
https://phirewall.de/common-attacks.html#fail2ban-on-login-failures

How do I block SQL injection attempts?
======================================

SQL injection is detected in the *content* of a request (query string, body or
headers), which needs a rule engine rather than a simple block list. phirewall
supports the OWASP Core Rule Set (CRS): load the rules with `SecRuleLoader` and
register them as an OWASP blocklist, in `config/system/phirewall.php`.

..  tabs::

    ..  group-tab:: config/system/phirewall.php

        ..  code-block:: php

            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Owasp\SecRuleLoader;
            use Flowd\Phirewall\Store\ApcuCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new ApcuCache(), $eventDispatcher);
                $rules = SecRuleLoader::fromString(<<<'CRS'
                SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" \
                    "id:942100,phase:2,deny,msg:'SQL Injection: UNION SELECT'"
                CRS);
                $config->blocklists->owasp('sqli', $rules);
                return $config;
            };

The example shows one rule; in practice you load the full OWASP CRS SQLi
ruleset. Full guide: https://phirewall.de/common-attacks.html

How do I handle a crawler that is slowing down my site?
=======================================================

..  note::

    Blocking by User-Agent only works for crawlers that identify themselves
    honestly. Some have been observed evading controls – `Cloudflare reported
    <https://blog.cloudflare.com/perplexity-is-using-stealth-undeclared-crawlers-to-evade-website-no-crawl-directives/>`__
    that Perplexity spoofed an ordinary browser User-Agent and ignored
    `robots.txt` – so they cannot be stopped by User-Agent rules; they need
    behaviour-based or edge defences.

The right response depends on which crawler it is:

- **Search engines and AI assistants** – Googlebot and Bingbot, plus the
  assistants' search and retrieval bots (OpenAI's `OAI-SearchBot` and
  `ChatGPT-User`, Anthropic's `Claude-SearchBot` and `Claude-User`) – **should
  generally not be blocked**. They are how people find, and are referred to,
  your site – increasingly through AI answers as well as classic search. To
  ease the load instead:

  - **Bing and Yandex** honour `robots.txt` `Crawl-delay`; **Googlebot ignores
    it.**
  - **Googlebot** treats repeated `429` / `503` responses as an overload signal
    and temporarily lowers its crawl rate site-wide, recovering once you serve
    `2xx` again. A throttle that returns `429` is therefore a valid way to slow
    it (it reacts to the status code; it does not promise to honour the exact
    `Retry-After` value).

- **AI training crawlers** – `GPTBot` (OpenAI), `ClaudeBot` (Anthropic) and
  `CCBot` (Common Crawl, widely used as training data). Blocking these is a
  content-policy choice: it controls whether your content is used to train AI
  models, but does not affect whether those tools can find or cite you. They
  honour `robots.txt`, which is the appropriate place to opt out.

- **SEO crawlers** – AhrefsBot, SemrushBot, MJ12bot and DotBot. Opt out via
  `robots.txt`, or block them at the firewall by User-Agent to enforce it.

..  tabs::

    ..  group-tab:: Backend Module

        Block SEO crawlers by their User-Agent: kind `header_regex`, target
        `User-Agent`, value `#(AhrefsBot|SemrushBot|MJ12bot|DotBot)#i` (regex
        values are full PCRE patterns *with* delimiters). Search engines and AI
        assistants use their own User-Agents and are not matched.

        To opt out of AI *training* (`GPTBot`, `ClaudeBot`, `CCBot`), use
        `robots.txt` rather than the firewall. To *slow* a
        wanted crawler rather than block it, a throttle in
        `config/system/phirewall.php` is the right tool (or `Crawl-delay` for
        Bing/Yandex).

    ..  group-tab:: config/system/phirewall.php

        Block the SEO crawlers by User-Agent, add a safelist so legitimate bots
        are never caught and to slow a wanted crawler rather than block it
        use a throttle keyed by its User-Agent (which responds with `429` and a
        `Retry-After` header).

        ..  code-block:: php

            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\Store\ApcuCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                $config = new Config(new ApcuCache(), $eventDispatcher);

                // Never block legitimate search engines. trustedBots() covers
                // the major verified crawlers: Googlebot, Bingbot, DuckDuckBot,
                // Baiduspider, YandexBot, Applebot and more.
                $config->safelists->trustedBots();

                $config->blocklists->add(
                    name: 'block-seo-crawlers',
                    callback: fn($request) => (bool) preg_match(
                        '#(AhrefsBot|SemrushBot|MJ12bot|DotBot)#i',
                        $request->getHeaderLine('User-Agent')
                    ),
                );

                return $config;
            };

    ..  group-tab:: robots.txt

        `robots.txt` is the right place to opt out of AI training and to ask
        well-behaved crawlers to stay away. It is advisory: compliant crawlers
        follow it, but it does not enforce anything – use the other tabs to
        enforce a block. Place the file at your site root,
        `https://example.com/robots.txt`.

        Opt out of AI training:

        ..  code-block:: text

            User-agent: GPTBot
            Disallow: /

            User-agent: ClaudeBot
            Disallow: /

            User-agent: CCBot
            Disallow: /

            User-agent: Google-Extended
            Disallow: /

        Keep SEO crawlers out:

        ..  code-block:: text

            User-agent: AhrefsBot
            Disallow: /

            User-agent: SemrushBot
            Disallow: /

            User-agent: MJ12bot
            Disallow: /

            User-agent: DotBot
            Disallow: /

        Do not disallow `OAI-SearchBot` or `Claude-SearchBot` unless you want
        your site to stop appearing in AI search. `ChatGPT-User` is
        user-initiated, so robots.txt rules may not apply to it.


..  seealso::

    Official crawler documentation and behaviour:

    -   OpenAI (GPTBot, OAI-SearchBot, ChatGPT-User):
        https://developers.openai.com/api/docs/bots
    -   Anthropic (ClaudeBot, Claude-SearchBot, Claude-User):
        https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
    -   Common Crawl (CCBot): https://commoncrawl.org/ccbot
    -   Google (Googlebot, Google-Extended):
        https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers
    -   Bing (Bingbot, Crawl-delay):
        https://www.bing.com/webmasters/help/crawl-control-55a30303
    -   Ahrefs (AhrefsBot): https://ahrefs.com/robot
    -   Semrush (SemrushBot): https://www.semrush.com/bot/
    -   Majestic (MJ12bot): https://www.mj12bot.com/
    -   Moz (DotBot): https://moz.com/help/moz-procedures/crawlers/dotbot

Can I block traffic from specific countries?
============================================

Geo-blocking is best handled at the **edge** (CDN/WAF). Inside
TYPO3 there is no reliable country signal, maintaining per-country IP ranges by
hand goes stale fast, and even done well it is blunt: it blocks real visitors,
expats and VPN users, while attackers just switch countries.

Filtering on **behaviour rather than origin** is the more reliable approach –
blocking obvious scanner paths and slowing down abusive clients (see the starter
set below) catches malicious traffic regardless of where it comes from. If
geo-blocking is a hard requirement (sanctions/compliance), it belongs at the
hosting/CDN layer.

What is a good set of rules to start with?
==========================================

Starting conservative and tightening based on your logs is the safer path, since
over-blocking hurts real visitors.

..  note::

    Throttles and Fail2Ban need a **persistent cache** (APCu/Redis); with
    `InMemoryCache` counters reset every request. Behind a load balancer/proxy,
    the real client IP is resolved with
    `KeyExtractors::clientIp(new TrustedProxyResolver([...]))`. Banning by
    counting requests to the backend login is risky: the firewall runs before
    TYPO3 and cannot tell a failed login from a normal one, so it would lock out
    real editors. Banning on clearly malicious behaviour is the safer signal.

..  tabs::

    ..  group-tab:: Backend Module

        Add a couple of block patterns for obvious junk:

        - Scanner / exploit probes – add one pattern of kind `path_prefix` for
          each path that never exists in a normal TYPO3 site: `/wp-admin`,
          `/wp-login`, `/xmlrpc.php`, `/.env`, `/.git`. A `path_prefix` matches
          any URL starting with that value, so no regular expressions are
          needed.
        - Known bad networks as you spot them in logs – kind `cidr` (a network
          range) or `ip` (a single address), with an `expiresAt` so stale
          entries clean themselves up.

    ..  group-tab:: config/system/phirewall.php

        A fuller baseline – a persistent cache, a safelist for good bots, the
        scanner block, and a gentle global ceiling:

        ..  code-block:: php

            <?php
            use Flowd\Phirewall\Config;
            use Flowd\Phirewall\KeyExtractors;
            use Flowd\Phirewall\Store\ApcuCache;
            use Psr\EventDispatcher\EventDispatcherInterface;

            return function (EventDispatcherInterface $eventDispatcher): Config {
                // Persistent cache so rate limits and bans survive between requests.
                $config = new Config(new ApcuCache(), $eventDispatcher);

                // Never block legitimate search engines. trustedBots() covers
                // the major verified crawlers: Googlebot, Bingbot, DuckDuckBot,
                // Baiduspider, YandexBot, Applebot and more.
                $config->safelists->trustedBots();

                // Block obvious scanner / exploit probes.
                $config->blocklists->add(
                    name: 'common-scanner-paths',
                    callback: fn($request) => (bool) preg_match(
                        '#^/(wp-admin|wp-login|xmlrpc\.php|\.env|\.git)#i',
                        $request->getUri()->getPath()
                    ),
                );

                // A gentle global ceiling against floods.
                $config->throttles->add(
                    name: 'global-rate-limit',
                    limit: 120,
                    period: 60,
                    key: KeyExtractors::ip(),
                );

                return $config;
            };

A legitimate visitor is blocked: how do I find out why?
=======================================================

..  tabs::

    ..  group-tab:: Backend Module

        Open the Firewall module. **Blocked keys** lists the addresses banned
        automatically by Fail2Ban or Allow2Ban, grouped by rule; **Patterns**
        lists the static blocks. If the visitor's IP matches an entry there,
        that is the cause – remove the entry to unblock them immediately.

    ..  group-tab:: config/system/phirewall.php

        In development or staging, enable diagnostic response headers:

        ..  code-block:: php

            $config->enableResponseHeaders();
            $config->enableOwaspDiagnosticsHeader(); // adds the OWASP rule id

        A blocked response then carries `X-Phirewall` (the block type),
        `X-Phirewall-Matched` (the rule name) and, for OWASP rules,
        `X-Phirewall-Owasp-Rule` (the rule id). phirewall also dispatches a
        PSR-14 event for every decision that you can log; and with the opt-in
        firewall middleware enabled, the decision is available through TYPO3's
        Context (`getAspect('firewall')`). Full guide:
        https://phirewall.de/faq.html#how-do-i-debug-which-rule-blocked-a-request

        ..  warning::

            Enable these headers only in development or staging. In production
            they reveal your security rules to attackers.

