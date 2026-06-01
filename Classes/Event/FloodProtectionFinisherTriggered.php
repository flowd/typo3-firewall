<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Event;

final class FloodProtectionFinisherTriggered
{
    public function __construct(
        public string $ruleIdentifier,
    ) {}
}
