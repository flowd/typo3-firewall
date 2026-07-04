<?php

declare(strict_types=1);

use Flowd\Typo3Firewall\Widgets\Provider\BlockedTodayDataProvider;
use Flowd\Typo3Firewall\Widgets\Provider\FirewallEventsChartDataProvider;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use TYPO3\CMS\Dashboard\Widgets\BarChartWidget;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconWidget;
use TYPO3\CMS\Dashboard\Widgets\WidgetInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder): void {
    // The dashboard widgets are only registered when the optional
    // typo3/cms-dashboard package is installed. A package check is not
    // possible here (the package manager is not available during container
    // compilation) and not needed: when the classes are merely autoloadable
    // but the extension is inactive, nothing consumes the dashboard.widget
    // tag and the unused widget services are dropped during compilation.
    if (!interface_exists(WidgetInterface::class)) {
        return;
    }

    $services = $containerConfigurator->services();
    $services->defaults()->autowire()->autoconfigure();

    $services->set(FirewallEventsChartDataProvider::class)->public();
    $services->set(BlockedTodayDataProvider::class)->public();

    $services->set('dashboard.widget.firewallBlockedToday', NumberWithIconWidget::class)
        ->arg('$dataProvider', service(BlockedTodayDataProvider::class))
        ->arg('$options', [
            'title' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.blockedToday.title',
            'subtitle' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.blockedToday.subtitle',
            'icon' => 'module-firewall',
        ])
        ->tag('dashboard.widget', [
            'identifier' => 'firewallBlockedToday',
            'groupNames' => 'systemInfo',
            'title' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.blockedToday.title',
            'description' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.blockedToday.description',
            'iconIdentifier' => 'module-firewall',
            'height' => 'small',
            'width' => 'small',
        ]);

    $services->set('dashboard.widget.firewallEvents', BarChartWidget::class)
        ->arg('$dataProvider', service(FirewallEventsChartDataProvider::class))
        ->tag('dashboard.widget', [
            'identifier' => 'firewallEvents',
            'groupNames' => 'systemInfo',
            'title' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.events.title',
            'description' => 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:widgets.events.description',
            'iconIdentifier' => 'module-firewall',
            'height' => 'medium',
            'width' => 'medium',
        ]);
};
