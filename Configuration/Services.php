<?php

declare(strict_types=1);

use Flowd\Typo3Firewall\Form\Finisher\FloodProtectionFinisher;
use Flowd\Typo3Firewall\Widgets\Provider\BlockedTodayDataProvider;
use Flowd\Typo3Firewall\Widgets\Provider\FirewallEventsChartDataProvider;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use TYPO3\CMS\Dashboard\Widgets\BarChartWidget;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconWidget;
use TYPO3\CMS\Dashboard\Widgets\WidgetInterface;
use TYPO3\CMS\Form\Domain\Finishers\FinisherInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder): void {
    $services = $containerConfigurator->services();
    $services->defaults()->autowire()->autoconfigure();

    // Services below depend on optional packages and are only registered when
    // those are installed. A package check is not possible here (the package
    // manager is not available during container compilation) and not needed:
    // when the classes are merely autoloadable but the extension is inactive,
    // nothing consumes their tags and the unused services are dropped during
    // compilation.

    // typo3/cms-form: EXT:form's autoconfiguration tags the finisher as
    // form.finisher, which makes it a public prototype service so the form
    // framework can instantiate it with dependency injection.
    if (interface_exists(FinisherInterface::class)) {
        $services->set(FloodProtectionFinisher::class);
    }

    // typo3/cms-dashboard: the firewall dashboard widgets.
    if (!interface_exists(WidgetInterface::class)) {
        return;
    }

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
