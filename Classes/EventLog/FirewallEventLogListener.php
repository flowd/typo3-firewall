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
        $this->eventLogger->log(FirewallEventType::BlocklistMatched, $blocklistMatched->serverRequest, rule: $blocklistMatched->rule, meta: $this->diagnosticMeta($blocklistMatched->matchResult ?? null));
    }

    public function onThrottleExceeded(ThrottleExceeded $throttleExceeded): void
    {
        $this->eventLogger->log(FirewallEventType::ThrottleExceeded, $throttleExceeded->serverRequest, rule: $throttleExceeded->rule, key: $throttleExceeded->key, meta: [
            'limit' => $throttleExceeded->limit,
            'period' => $throttleExceeded->period,
            'count' => $throttleExceeded->count,
            'retryAfter' => $throttleExceeded->retryAfter,
            ...$this->diagnosticMeta($throttleExceeded->matchResult ?? null),
        ]);
    }

    public function onFail2BanMatched(Fail2BanMatched $fail2BanMatched): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanMatched, $fail2BanMatched->serverRequest, rule: $fail2BanMatched->rule, key: $fail2BanMatched->key, meta: [
            'threshold' => $fail2BanMatched->threshold,
            'period' => $fail2BanMatched->period,
            'count' => $fail2BanMatched->count,
            ...$this->diagnosticMeta($fail2BanMatched->matchResult ?? null),
        ]);
    }

    public function onFail2BanBanned(Fail2BanBanned $fail2BanBanned): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanBanned, $fail2BanBanned->serverRequest, rule: $fail2BanBanned->rule, key: $fail2BanBanned->key, banType: BanType::Fail2Ban->value, meta: [
            'threshold' => $fail2BanBanned->threshold,
            'period' => $fail2BanBanned->period,
            'banSeconds' => $fail2BanBanned->banSeconds,
            'count' => $fail2BanBanned->count,
            ...$this->diagnosticMeta($fail2BanBanned->matchResult ?? null),
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
            ...$this->diagnosticMeta($allow2BanBanned->matchResult ?? null),
        ]);
    }

    public function onAllow2BanBlocked(Allow2BanBlocked $allow2BanBlocked): void
    {
        $this->eventLogger->log(FirewallEventType::Allow2BanBlocked, $allow2BanBlocked->serverRequest, rule: $allow2BanBlocked->rule, key: $allow2BanBlocked->key, banType: BanType::Allow2Ban->value);
    }

    public function onSafelistMatched(SafelistMatched $safelistMatched): void
    {
        $this->eventLogger->log(FirewallEventType::SafelistMatched, $safelistMatched->serverRequest, rule: $safelistMatched->rule, meta: $this->diagnosticMeta($safelistMatched->matchResult ?? null));
    }

    public function onTrackHit(TrackHit $trackHit): void
    {
        $this->eventLogger->log(FirewallEventType::TrackHit, $trackHit->serverRequest, rule: $trackHit->rule, key: $trackHit->key, meta: [
            'period' => $trackHit->period,
            'count' => $trackHit->count,
            'limit' => $trackHit->limit,
            ...$this->diagnosticMeta($trackHit->matchResult ?? null),
        ]);
    }

    public function onFirewallError(FirewallError $firewallError): void
    {
        $this->eventLogger->log(FirewallEventType::FirewallError, $firewallError->serverRequest, meta: [
            'exceptionClass' => $firewallError->exception::class,
            'exceptionMessage' => mb_substr($firewallError->exception->getMessage(), 0, 500),
        ]);
    }

    /**
     * Extract the matcher's diagnostic headers as a meta fragment. Events from
     * phirewall versions without the matchResult property yield no fragment.
     *
     * @return array<string, array<string, string>>
     */
    private function diagnosticMeta(?MatchResult $matchResult): array
    {
        $headers = $matchResult?->metadata()['diagnostic_headers'] ?? null;
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
