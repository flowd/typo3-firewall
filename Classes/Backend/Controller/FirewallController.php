<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend\Controller;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Pattern\PatternValidationException;
use Flowd\Typo3Firewall\Statistics\BarChartBuilder;
use Flowd\Typo3Firewall\Statistics\EventStatisticsRepository;
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
    /**
     * Maps the validation exception codes of PatternEntryDto and
     * PatternEntryValidator to translation keys.
     */
    private const array VALIDATION_MESSAGE_KEYS = [
        1779107801 => 'flash.validation.invalidKind',
        1779107802 => 'flash.validation.invalidExpiresAt',
        1779107803 => 'flash.validation.expiresAtNotInFuture',
        1770244701 => 'flash.validation.emptyValue',
        1779136101 => 'flash.validation.targetRequired',
        1770244710 => 'flash.validation.invalidIp',
        1770244715 => 'flash.validation.invalidCidr',
        1770244720 => 'flash.validation.invalidRegex',
    ];

    /**
     * @var array<string, array{window: int, bucket: int, labelFormat: string}>
     */
    private const array STATISTICS_RANGES = [
        '24h' => ['window' => 86400, 'bucket' => 3600, 'labelFormat' => 'H:00'],
        '7d' => ['window' => 604800, 'bucket' => 86400, 'labelFormat' => 'd.m.'],
        '30d' => ['window' => 2592000, 'bucket' => 86400, 'labelFormat' => 'd.m.'],
    ];

    private ?FileArrayPatternBackend $fileArrayPatternBackend = null;

    public function __construct(
        private readonly ModuleTemplateFactory $moduleTemplateFactory,
        private readonly Config $config,
        private readonly EventStatisticsRepository $eventStatisticsRepository,
        private readonly BarChartBuilder $barChartBuilder,
        private readonly EventLogSettings $eventLogSettings,
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
                $this->addFlashMessage($this->translateLabel('flash.pattern.notFound'), $this->translateLabel('flash.title.error'), ContextualFeedbackSeverity::ERROR);
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
            $this->addFlashMessage($this->translateLabel('flash.pattern.created'));
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($this->translateValidationError($invalidArgumentException), $this->translateLabel('flash.title.validationError'), ContextualFeedbackSeverity::ERROR);
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

            $this->addFlashMessage($this->translateLabel('flash.pattern.updated'));
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($this->translateValidationError($invalidArgumentException), $this->translateLabel('flash.title.validationError'), ContextualFeedbackSeverity::ERROR);
            return $this->redirect('overview', null, null, ['editId' => $id]);
        }

        return $this->redirect('overview');
    }

    public function deleteAction(string $id): ResponseInterface
    {
        $this->getBackend()->removeById($id);
        $this->addFlashMessage($this->translateLabel('flash.pattern.deleted'));
        return $this->redirect('overview');
    }

    public function pruneAction(): ResponseInterface
    {
        $this->getBackend()->pruneExpired();
        $this->addFlashMessage($this->translateLabel('flash.pattern.pruned'));
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

    public function statisticsAction(string $range = '24h'): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $this->addModuleMenu($moduleTemplate, 'statistics');

        if (!isset(self::STATISTICS_RANGES[$range])) {
            $range = '24h';
        }

        $rangeConfiguration = self::STATISTICS_RANGES[$range];
        $now = time();
        $since = $now - $rangeConfiguration['window'];
        $startOfToday = (new \DateTimeImmutable('today'))->getTimestamp();

        $chart = $this->barChartBuilder->build(
            $this->eventStatisticsRepository->countBlockingEventsPerBucketAndType($since, $rangeConfiguration['bucket']),
            $since,
            $now,
            $rangeConfiguration['bucket'],
            $rangeConfiguration['labelFormat']
        );

        $eventCounts = $this->eventStatisticsRepository->countEventsByTypeSince($since);
        $typeCounts = [];
        foreach ($eventCounts as $eventType => $count) {
            $typeCounts[] = ['type' => $eventType, 'count' => $count];
        }

        $moduleTemplate->assignMultiple([
            'blockedToday' => $this->eventStatisticsRepository->countDistinctBlockedKeysSince($startOfToday),
            'chart' => $chart,
            'typeCounts' => $typeCounts,
            'topRules' => $this->eventStatisticsRepository->findTopRulesSince($since),
            'topPaths' => $this->eventStatisticsRepository->findTopPathsSince($since),
            'range' => $range,
            'ranges' => array_keys(self::STATISTICS_RANGES),
            'loggingEnabled' => $this->eventLogSettings->isEnabled(),
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Statistics');
    }

    public function unbanAction(string $rule, string $key, string $type): ResponseInterface
    {
        $banType = BanType::tryFrom($type);
        if (!$banType instanceof BanType) {
            $this->addFlashMessage(sprintf($this->translateLabel('flash.ban.unknownType'), $type), $this->translateLabel('flash.title.error'), ContextualFeedbackSeverity::ERROR);
            return $this->redirect('bans');
        }

        $unbanned = $this->config->banManager()->unban($rule, $key, $banType);
        if ($unbanned) {
            $this->addFlashMessage(sprintf($this->translateLabel('flash.ban.removed'), $key));
        } else {
            $this->addFlashMessage($this->translateLabel('flash.ban.notFound'), $this->translateLabel('flash.title.notFound'), ContextualFeedbackSeverity::WARNING);
        }

        return $this->redirect('bans');
    }

    private function addModuleMenu(ModuleTemplate $moduleTemplate, string $currentAction): void
    {
        $menuRegistry = $moduleTemplate->getDocHeaderComponent()->getMenuRegistry();
        $menu = $menuRegistry->makeMenu();
        $menu->setIdentifier('firewallModuleMenu');
        $menu->setLabel($this->translateLabel('nav.label'));

        $items = [
            'overview' => 'nav.patterns',
            'bans' => 'nav.bans',
            'statistics' => 'nav.statistics',
        ];

        foreach ($items as $action => $labelKey) {
            $menu->addMenuItem(
                $menu->makeMenuItem()
                    ->setTitle($this->translateLabel($labelKey))
                    ->setHref($this->uriBuilder->reset()->uriFor($action))
                    ->setActive($currentAction === $action),
            );
        }

        $menuRegistry->addMenu($menu);
    }

    private function translateLabel(string $key): string
    {
        return $this->getLanguageService()->sL('LLL:EXT:firewall/Resources/Private/Language/locallang.xlf:' . $key);
    }

    /**
     * Unknown codes keep the raw exception message as fallback.
     */
    private function translateValidationError(\InvalidArgumentException $invalidArgumentException): string
    {
        $translationKey = self::VALIDATION_MESSAGE_KEYS[$invalidArgumentException->getCode()] ?? null;
        if ($translationKey === null || !$invalidArgumentException instanceof PatternValidationException) {
            return $invalidArgumentException->getMessage();
        }

        return sprintf($this->translateLabel($translationKey), $invalidArgumentException->getInvalidValue());
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
