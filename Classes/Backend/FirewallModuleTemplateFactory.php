<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend;

use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Backend\Template\Components\ButtonBar;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Extbase\Mvc\RequestInterface;

/**
 * Builds the firewall module's ModuleTemplate: loads the module assets, the
 * view menu, the title, the bookmark button, and the backend date formats.
 */
final class FirewallModuleTemplateFactory
{
    private const string ROUTE_IDENTIFIER = 'system_firewall';

    /** View action to navigation label. */
    private const array ACTION_LABELS = [
        'overview' => 'nav.patterns',
        'bans' => 'nav.bans',
        'events' => 'nav.events',
        'statistics' => 'nav.statistics',
    ];

    public function __construct(
        private readonly ModuleTemplateFactory $moduleTemplateFactory,
        private readonly PageRenderer $pageRenderer,
        private readonly UriBuilder $uriBuilder,
    ) {}

    public function create(RequestInterface $request, string $currentAction): ModuleTemplate
    {
        $this->pageRenderer->addCssFile('EXT:firewall/Resources/Public/Css/backend.css');
        $this->pageRenderer->loadJavaScriptModule('@typo3/backend/modal.js');

        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $this->addModuleMenu($moduleTemplate, $currentAction);

        $moduleTitle = $this->translate('LLL:EXT:firewall/Resources/Private/Language/locallang_mod.xlf:mlang_tabs_tab');
        $viewTitle = $this->translateLabel(self::ACTION_LABELS[$currentAction] ?? 'nav.label');
        $moduleTemplate->setTitle($moduleTitle, $viewTitle);
        $this->addShortcutButton($moduleTemplate, $currentAction, sprintf('%s: %s', $moduleTitle, $viewTitle));

        $moduleTemplate->assignMultiple($this->resolveSystemDateTimeFormats());

        return $moduleTemplate;
    }

    private function addModuleMenu(ModuleTemplate $moduleTemplate, string $currentAction): void
    {
        $menuRegistry = $moduleTemplate->getDocHeaderComponent()->getMenuRegistry();
        $menu = $menuRegistry->makeMenu();
        $menu->setIdentifier('firewallModuleMenu');
        $menu->setLabel($this->translateLabel('nav.label'));

        foreach (self::ACTION_LABELS as $action => $labelKey) {
            $menu->addMenuItem(
                $menu->makeMenuItem()
                    ->setTitle($this->translateLabel($labelKey))
                    ->setHref((string)$this->uriBuilder->buildUriFromRoute(self::ROUTE_IDENTIFIER, ['action' => $action]))
                    ->setActive($currentAction === $action),
            );
        }

        $menuRegistry->addMenu($menu);
    }

    private function addShortcutButton(ModuleTemplate $moduleTemplate, string $currentAction, string $displayName): void
    {
        $buttonBar = $moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $shortcutButton = $buttonBar->makeShortcutButton()
            ->setRouteIdentifier(self::ROUTE_IDENTIFIER)
            ->setArguments(['action' => $currentAction])
            ->setDisplayName($displayName);
        $buttonBar->addButton($shortcutButton, ButtonBar::BUTTON_POSITION_RIGHT);
    }

    /**
     * The backend date and time formats configured in SYS.ddmmyy and
     * SYS.hhmm, with the core defaults as fallback.
     *
     * @return array{dateFormat: string, timeFormat: string}
     */
    private function resolveSystemDateTimeFormats(): array
    {
        $systemConfiguration = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $sysSection = is_array($systemConfiguration) && is_array($systemConfiguration['SYS'] ?? null) ? $systemConfiguration['SYS'] : [];
        $dateFormat = $sysSection['ddmmyy'] ?? null;
        $timeFormat = $sysSection['hhmm'] ?? null;

        return [
            'dateFormat' => is_string($dateFormat) && $dateFormat !== '' ? $dateFormat : 'd-m-Y',
            'timeFormat' => is_string($timeFormat) && $timeFormat !== '' ? $timeFormat : 'H:i',
        ];
    }

    private function translateLabel(string $key): string
    {
        return $this->translate('LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:' . $key);
    }

    private function translate(string $key): string
    {
        return $this->getLanguageService()->sL($key);
    }

    private function getLanguageService(): LanguageService
    {
        /** @var LanguageService $languageService */
        $languageService = $GLOBALS['LANG'];
        return $languageService;
    }
}
