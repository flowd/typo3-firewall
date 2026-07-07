<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Event;

/**
 * Dispatched before the FloodProtectionFinisher reports a submission.
 * Listeners can change the allow2ban rule the submission counts against,
 * or set an empty identifier to skip the submission entirely.
 */
final class FloodProtectionFinisherTriggered
{
    public function __construct(
        public string $ruleIdentifier,
    ) {}
}
