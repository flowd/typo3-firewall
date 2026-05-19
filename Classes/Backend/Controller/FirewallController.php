<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend\Controller;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

#[AsController]
class FirewallController extends ActionController
{
    private ?FileArrayPatternBackend $fileArrayPatternBackend = null;

    public function __construct(
        private readonly ModuleTemplateFactory $moduleTemplateFactory,
        private readonly Config $config,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function overviewAction(?string $editId = null): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $this->addModuleMenu($moduleTemplate, 'overview');
        $fileArrayPatternBackend = $this->getBackend();

        $editPattern = null;
        if ($editId !== null) {
            $editPattern = $this->findPatternById($editId);
            if ($editPattern === null) {
                $this->addFlashMessage('Pattern not found.', 'Error', ContextualFeedbackSeverity::ERROR);
            }
        }

        $moduleTemplate->assignMultiple([
            'patterns' => $fileArrayPatternBackend->listRaw(),
            'kinds' => PatternKind::cases(),
            'now' => time(),
            'editPattern' => $editPattern,
            'isEditMode' => $editPattern !== null,
            'integrityIssue' => $fileArrayPatternBackend->checkIntegrity(),
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Overview');
    }

    public function createAction(PatternEntryDto $patternEntryDto): ResponseInterface
    {
        try {
            $this->getBackend()->append($patternEntryDto->toPatternEntry());
            $this->addFlashMessage('Pattern created successfully.');
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($invalidArgumentException->getMessage(), 'Validation Error', ContextualFeedbackSeverity::ERROR);
        }

        return $this->redirect('overview');
    }

    public function updateAction(string $id, PatternEntryDto $patternEntryDto): ResponseInterface
    {
        try {
            $entry = $patternEntryDto->toPatternEntry();
            $this->getBackend()->append(new PatternEntry(
                kind: $entry->kind,
                value: $entry->value,
                target: $entry->target,
                expiresAt: $entry->expiresAt,
                metadata: ['id' => $id],
            ));

            $this->addFlashMessage('Pattern updated successfully.');
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($invalidArgumentException->getMessage(), 'Validation Error', ContextualFeedbackSeverity::ERROR);
            return $this->redirect('overview', null, null, ['editId' => $id]);
        }

        return $this->redirect('overview');
    }

    public function deleteAction(string $id): ResponseInterface
    {
        $this->getBackend()->removeById($id);
        $this->addFlashMessage('Pattern deleted successfully.');
        return $this->redirect('overview');
    }

    public function pruneAction(): ResponseInterface
    {
        $this->getBackend()->pruneExpired();
        $this->addFlashMessage('Expired patterns pruned.');
        return $this->redirect('overview');
    }

    public function bansAction(): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $this->addModuleMenu($moduleTemplate, 'bans');
        $banManager = $this->config->banManager();

        $banGroups = [];
        $totalBans = 0;

        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $bans = $banManager->listBans($allow2BanRule->name(), BanType::Allow2Ban);
            if ($bans === []) {
                continue;
            }

            $banGroups[] = [
                'rule' => $allow2BanRule->name(),
                'type' => BanType::Allow2Ban->value,
                'bans' => $this->formatBans($bans),
            ];
            $totalBans += count($bans);
        }

        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $bans = $banManager->listBans($fail2BanRule->name(), BanType::Fail2Ban);
            if ($bans === []) {
                continue;
            }

            $banGroups[] = [
                'rule' => $fail2BanRule->name(),
                'type' => BanType::Fail2Ban->value,
                'bans' => $this->formatBans($bans),
            ];
            $totalBans += count($bans);
        }

        $moduleTemplate->assignMultiple([
            'banGroups' => $banGroups,
            'totalBans' => $totalBans,
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Bans');
    }

    public function unbanAction(string $rule, string $key, string $type): ResponseInterface
    {
        $banType = BanType::tryFrom($type);
        if ($banType === null) {
            $this->addFlashMessage('Unknown ban type: ' . $type, 'Error', ContextualFeedbackSeverity::ERROR);
            return $this->redirect('bans');
        }

        $unbanned = $this->config->banManager()->unban($rule, $key, $banType);
        if ($unbanned) {
            $this->addFlashMessage('Ban removed for key "' . $key . '".');
        } else {
            $this->addFlashMessage('Ban not found or already expired.', 'Not Found', ContextualFeedbackSeverity::WARNING);
        }

        return $this->redirect('bans');
    }

    private function addModuleMenu(ModuleTemplate $moduleTemplate, string $currentAction): void
    {
        $menuRegistry = $moduleTemplate->getDocHeaderComponent()->getMenuRegistry();
        $menu = $menuRegistry->makeMenu();
        $menu->setIdentifier('firewallModuleMenu');
        $menu->setLabel($this->getLanguageService()->sL('LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:nav.label'));

        $items = [
            'overview' => 'nav.patterns',
            'bans' => 'nav.bans',
        ];

        foreach ($items as $action => $labelKey) {
            $menu->addMenuItem(
                $menu->makeMenuItem()
                    ->setTitle($this->getLanguageService()->sL('LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:' . $labelKey))
                    ->setHref($this->uriBuilder->reset()->uriFor($action))
                    ->setActive($currentAction === $action),
            );
        }

        $menuRegistry->addMenu($menu);
    }

    private function getLanguageService(): LanguageService
    {
        /** @var LanguageService $languageService */
        $languageService = $GLOBALS['LANG'];
        return $languageService;
    }

    /**
     * @param list<array{key: string, expiresAt: float}> $bans
     * @return list<array{key: string, expiresAt: int}>
     */
    private function formatBans(array $bans): array
    {
        return array_map(
            static fn(array $ban): array => [
                'key' => $ban['key'],
                'expiresAt' => (int)$ban['expiresAt'],
            ],
            $bans,
        );
    }

    private function getBackend(): FileArrayPatternBackend
    {
        if ($this->fileArrayPatternBackend instanceof FileArrayPatternBackend) {
            return $this->fileArrayPatternBackend;
        }

        $path = ConfigFactory::getPatternsFilePath();
        return $this->fileArrayPatternBackend = new FileArrayPatternBackend(
            $path,
            new FileArrayWriter($path, $this->logger),
            $this->logger
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findPatternById(string $id): ?array
    {
        $patterns = $this->getBackend()->listRaw();
        foreach ($patterns as $pattern) {
            if (($pattern['id'] ?? null) === $id) {
                return $pattern;
            }
        }

        return null;
    }
}
