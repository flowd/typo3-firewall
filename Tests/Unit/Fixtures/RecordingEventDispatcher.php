<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Fixtures;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Test double that records dispatched events and optionally lets a test mutate
 * the event (to simulate a real listener) before it is returned.
 */
final class RecordingEventDispatcher implements EventDispatcherInterface
{
    public int $dispatchCount = 0;

    public ?object $lastEvent = null;

    /** @var (\Closure(object): void)|null */
    public ?\Closure $mutator = null;

    public function dispatch(object $event): object
    {
        $this->dispatchCount++;
        $this->lastEvent = $event;

        if ($this->mutator instanceof \Closure) {
            ($this->mutator)($event);
        }

        return $event;
    }
}
