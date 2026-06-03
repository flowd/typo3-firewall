<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

// Input fixture: a phirewall.php as a site would ship it. Returns a Config with
// one custom fail2ban rule. ConfigFactory loads it and layers the TYPO3-managed
// patterns blocklist (and form-flood, if enabled) on top.
return static function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new InMemoryCache(), $eventDispatcher);

    $config->fail2ban->add(
        'custom-rule',
        threshold: 3,
        period: 60,
        ban: 600,
        filter: static fn(): bool => false,
        key: KeyExtractors::ip(),
    );

    return $config;
};
