<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Events\Allow2BanBanned;
use Flowd\Phirewall\Events\BlocklistMatched;
use Flowd\Phirewall\Events\Fail2BanBanned;
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
 */
final class FirewallEventLogListener
{
    public function __construct(
        private readonly EventLogger $eventLogger,
    ) {}

    public function onBlocklistMatched(BlocklistMatched $blocklistMatched): void
    {
        $this->eventLogger->log(FirewallEventType::BlocklistMatched, $blocklistMatched->serverRequest, rule: $blocklistMatched->rule);
    }

    public function onThrottleExceeded(ThrottleExceeded $throttleExceeded): void
    {
        $this->eventLogger->log(FirewallEventType::ThrottleExceeded, $throttleExceeded->serverRequest, rule: $throttleExceeded->rule, key: $throttleExceeded->key, meta: [
            'limit' => $throttleExceeded->limit,
            'period' => $throttleExceeded->period,
            'count' => $throttleExceeded->count,
            'retryAfter' => $throttleExceeded->retryAfter,
        ]);
    }

    public function onFail2BanMatched(Fail2BanMatched $fail2BanMatched): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanMatched, $fail2BanMatched->serverRequest, rule: $fail2BanMatched->rule, key: $fail2BanMatched->key, meta: [
            'threshold' => $fail2BanMatched->threshold,
            'period' => $fail2BanMatched->period,
            'count' => $fail2BanMatched->count,
        ]);
    }

    public function onFail2BanBanned(Fail2BanBanned $fail2BanBanned): void
    {
        $this->eventLogger->log(FirewallEventType::Fail2BanBanned, $fail2BanBanned->serverRequest, rule: $fail2BanBanned->rule, key: $fail2BanBanned->key, banType: BanType::Fail2Ban->value, meta: [
            'threshold' => $fail2BanBanned->threshold,
            'period' => $fail2BanBanned->period,
            'banSeconds' => $fail2BanBanned->banSeconds,
            'count' => $fail2BanBanned->count,
        ]);
    }

    public function onAllow2BanBanned(Allow2BanBanned $allow2BanBanned): void
    {
        $this->eventLogger->log(FirewallEventType::Allow2BanBanned, $allow2BanBanned->serverRequest, rule: $allow2BanBanned->rule, key: $allow2BanBanned->key, banType: BanType::Allow2Ban->value, meta: [
            'threshold' => $allow2BanBanned->threshold,
            'period' => $allow2BanBanned->period,
            'banSeconds' => $allow2BanBanned->banSeconds,
            'count' => $allow2BanBanned->count,
        ]);
    }

    public function onSafelistMatched(SafelistMatched $safelistMatched): void
    {
        $this->eventLogger->log(FirewallEventType::SafelistMatched, $safelistMatched->serverRequest, rule: $safelistMatched->rule);
    }

    public function onTrackHit(TrackHit $trackHit): void
    {
        $this->eventLogger->log(FirewallEventType::TrackHit, $trackHit->serverRequest, rule: $trackHit->rule, key: $trackHit->key, meta: [
            'period' => $trackHit->period,
            'count' => $trackHit->count,
            'limit' => $trackHit->limit,
        ]);
    }

    public function onFirewallError(FirewallError $firewallError): void
    {
        $this->eventLogger->log(FirewallEventType::FirewallError, $firewallError->serverRequest, meta: [
            'exceptionClass' => $firewallError->exception::class,
            'exceptionMessage' => mb_substr($firewallError->exception->getMessage(), 0, 500),
        ]);
    }
}
