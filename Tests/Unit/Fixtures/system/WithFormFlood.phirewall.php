<?php

declare(strict_types=1);

use Flowd\Phirewall\Config;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Store\InMemoryCache;
use Psr\EventDispatcher\EventDispatcherInterface;

// Input fixture defining its own "form-flood" rule. ConfigFactory must leave it
// untouched even when form flooding protection is enabled via extension config
// (file takes precedence over the generated default rule).
return static function (EventDispatcherInterface $eventDispatcher): Config {
    $config = new Config(new InMemoryCache(), $eventDispatcher);

    $config->fail2ban->add(
        'form-flood',
        threshold: 99,
        period: 99,
        ban: 99,
        filter: static fn(): bool => false,
        key: KeyExtractors::ip(),
    );

    return $config;
};
