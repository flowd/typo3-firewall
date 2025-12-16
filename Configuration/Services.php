<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;

return static function (ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder): void {
    $defaultsConfigurator = $containerConfigurator->services()->defaults()->autoconfigure()->autowire()->private();

    $defaultsConfigurator->load('Flowd\\Typo3Firewall\\', '../Classes/*');

    Extension::loadVendorLibraries();

    $defaultsConfigurator->set(Middleware::class)
        ->public()
        ->arg('$config', new Reference(Config::class));

    $defaultsConfigurator->set(Config::class)
        ->factory([new Reference(ConfigFactory::class), 'fromConfigurationFile']);
};
