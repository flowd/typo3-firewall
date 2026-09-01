<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\Allow2BanBlocked;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
use Flowd\Phirewall\Events\Fail2BanBlocked;
use Flowd\Phirewall\Events\Fail2BanMatched;
use Flowd\Phirewall\Events\FirewallError;
use Flowd\Phirewall\Events\SafelistMatched;
use Flowd\Phirewall\Events\ThrottleExceeded;
use Flowd\Phirewall\Events\TrackHit;

/**
 * Maps the phirewall PSR-14 events to event log entries.
 *
 * The listener methods are registered via event.listener tags in
 * Services.yaml because the AsEventListener attribute needs TYPO3 13.
 *
 * PerformanceMeasured is intentionally not logged: it fires on every
 * request and would turn the log into a request log.
 *
 * One public method per phirewall event; the method count grows with the
 * event catalog, not with complexity.
 *
 * @SuppressWarnings("PHPMD.TooManyPublicMethods")
 */
final class FirewallEventLogListener
{
    public function __construct(
        private readonly EventLogger $eventLogger,
    ) {}

    public function onBlocklistMatched(BlocklistMatched $blocklistMatched): void
    {
        $this->eventLogger->log(FirewallEventType::BlocklistMatched, $blocklistMatched->serverRequest, rule: $blocklistMatched->rule, meta: $this->matchMeta($blocklistMatched->matchResult));
    }

    public function onThrottleExceeded(ThrottleExceeded $throttleExceeded): void
    {
        $this->eventLogger->log(FirewallEventType::ThrottleExceeded, $throttleExceeded->serverRequest, rule: $throttleExceeded->rule, key: $throttleExceeded->key, meta: [
            'limit' => $throttleExceeded->limit,
            'period' => $throttleExceeded->period,
            'count' => $throttleExceeded->count,
            'retryAfter' => $throttleExceeded->retryAfter,
            ...$this->matchMeta($throttleExceeded->matchResult),
        ]);
    }

    public function onFail2BanMatched(Fail2BanMatched $fail2BanMatched): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanMatched, $fail2BanMatched->serverRequest, rule: $fail2BanMatched->rule, key: $fail2BanMatched->key, meta: [
            'threshold' => $fail2BanMatched->threshold,
            'period' => $fail2BanMatched->period,
            'count' => $fail2BanMatched->count,
            ...$this->matchMeta($fail2BanMatched->matchResult),
        ]);
    }

    public function onFail2BanBanned(Fail2BanBanned $fail2BanBanned): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanBanned, $fail2BanBanned->serverRequest, rule: $fail2BanBanned->rule, key: $fail2BanBanned->key, banType: BanType::Fail2Ban->value, meta: [
            'threshold' => $fail2BanBanned->threshold,
            'period' => $fail2BanBanned->period,
            'banSeconds' => $fail2BanBanned->banSeconds,
            'count' => $fail2BanBanned->count,
            ...$this->matchMeta($fail2BanBanned->matchResult),
        ]);
    }

    public function onFail2BanBlocked(Fail2BanBlocked $fail2BanBlocked): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanBlocked, $fail2BanBlocked->serverRequest, rule: $fail2BanBlocked->rule, key: $fail2BanBlocked->key, banType: BanType::Fail2Ban->value);
    }

    public function onAllow2BanBanned(Allow2BanBanned $allow2BanBanned): void
    {
        $this->eventLogger->log(FirewallEventType::Allow2BanBanned, $allow2BanBanned->serverRequest, rule: $allow2BanBanned->rule, key: $allow2BanBanned->key, banType: BanType::Allow2Ban->value, meta: [
            'threshold' => $allow2BanBanned->threshold,
            'period' => $allow2BanBanned->period,
            'banSeconds' => $allow2BanBanned->banSeconds,
            'count' => $allow2BanBanned->count,
            ...$this->matchMeta($allow2BanBanned->matchResult),
        ]);
    }

    public function onAllow2BanBlocked(Allow2BanBlocked $allow2BanBlocked): void
    {
        $this->eventLogger->log(FirewallEventType::Allow2BanBlocked, $allow2BanBlocked->serverRequest, rule: $allow2BanBlocked->rule, key: $allow2BanBlocked->key, banType: BanType::Allow2Ban->value);
    }

    public function onSafelistMatched(SafelistMatched $safelistMatched): void
    {
        $this->eventLogger->log(FirewallEventType::SafelistMatched, $safelistMatched->serverRequest, rule: $safelistMatched->rule, meta: $this->matchMeta($safelistMatched->matchResult));
    }

    public function onTrackHit(TrackHit $trackHit): void
    {
        $firewallEventType = $trackHit->thresholdReached
            ? FirewallEventType::TrackThresholdReached
            : FirewallEventType::TrackMatched;

        $this->eventLogger->log($firewallEventType, $trackHit->serverRequest, rule: $trackHit->rule, key: $trackHit->key, meta: [
            'period' => $trackHit->period,
            'count' => $trackHit->count,
            'limit' => $trackHit->limit,
            ...$this->matchMeta($trackHit->matchResult),
        ]);
    }

    public function onFirewallError(FirewallError $firewallError): void
    {
        $this->eventLogger->log(FirewallEventType::FirewallError, $firewallError->serverRequest, meta: [
            'exceptionClass' => $firewallError->exception::class,
            'exceptionMessage' => $this->scrubCredentials(mb_substr($firewallError->exception->getMessage(), 0, 500)),
        ]);
    }

    /**
     * Store backend errors may quote a connection DSN; strip the userinfo
     * part of any URL so credentials never reach the event log.
     */
    private function scrubCredentials(string $message): string
    {
        return (string)preg_replace('#://[^/@\s]+@#', '://***@', $message);
    }

    /**
     * The matcher's metadata as a meta fragment: scalar keys (rule id, msg,
     * matched variable and value, scores) pass through as the matcher logged
     * them - the OWASP matcher already sanitizes and redacts them - and the
     * diagnostic_headers fragment folds into diagnosticHeaders. Empty on the
     * signal-path events (no matcher ran).
     *
     * @return array<string, scalar|array<string, string>>
     */
    private function matchMeta(?MatchResult $matchResult): array
    {
        if (!$matchResult instanceof MatchResult) {
            return [];
        }

        $meta = [];
        foreach ($matchResult->metadata() as $name => $value) {
            if (is_scalar($value)) {
                $meta[$name] = $value;
            }
        }

        return [...$meta, ...$this->diagnosticHeadersMeta($matchResult)];
    }

    /**
     * The matcher's diagnostic headers as a meta fragment, empty on a match
     * without diagnostics.
     *
     * @return array<string, array<string, string>>
     */
    private function diagnosticHeadersMeta(MatchResult $matchResult): array
    {
        $headers = $matchResult->metadata()['diagnostic_headers'] ?? null;
        if (!is_array($headers)) {
            return [];
        }

        $stringHeaders = [];
        foreach ($headers as $name => $value) {
            if (is_string($name) && is_scalar($value)) {
                $stringHeaders[$name] = (string)$value;
            }
        }

        return $stringHeaders === [] ? [] : ['diagnosticHeaders' => $stringHeaders];
    }
}
