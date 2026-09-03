<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend\Controller;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Typo3Firewall\Backend\FirewallModuleState;
use Flowd\Typo3Firewall\Backend\FirewallModuleTemplateFactory;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use Flowd\Typo3Firewall\EventLog\BlockableKeyResolver;
use Flowd\Typo3Firewall\EventLog\EventLogViewDataProvider;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Pattern\PatternValidationException;
use Flowd\Typo3Firewall\Statistics\StatisticsViewDataProvider;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Extbase\Http\ForwardResponse;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Mvc\RequestInterface;

/**
 * One public method per backend view and mutation, so the public method
 * count grows with the module's actions, not with complexity.
 *
 * @SuppressWarnings("PHPMD.TooManyPublicMethods")
 */
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

    public function __construct(
        private readonly FirewallModuleTemplateFactory $firewallModuleTemplateFactory,
        private readonly FirewallModuleState $firewallModuleState,
        private readonly Config $config,
        private readonly StatisticsViewDataProvider $statisticsViewDataProvider,
        private readonly EventLogViewDataProvider $eventLogViewDataProvider,
        private readonly BlockableKeyResolver $blockableKeyResolver,
        private readonly FileArrayPatternBackend $fileArrayPatternBackend,
    ) {}

    /**
     * Remember an explicitly selected view as the module's default view.
     */
    public function processRequest(RequestInterface $request): ResponseInterface
    {
        $this->firewallModuleState->rememberSelectedView($request);

        return parent::processRequest($request);
    }

    /**
     * Module entry point: opens the view the user worked with last.
     */
    public function indexAction(): ForwardResponse
    {
        return new ForwardResponse($this->firewallModuleState->defaultView($this->request));
    }

    public function overviewAction(?string $editId = null): ResponseInterface
    {
        $moduleTemplate = $this->firewallModuleTemplateFactory->create($this->request, 'overview');
        $fileArrayPatternBackend = $this->fileArrayPatternBackend;

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
            $this->fileArrayPatternBackend->append($patternEntryDto->toPatternEntry());
            $this->addFlashMessage($this->translateLabel('flash.pattern.created'));
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($this->translateValidationError($invalidArgumentException), $this->translateLabel('flash.title.validationError'), ContextualFeedbackSeverity::ERROR);
        }

        return $this->redirect('overview');
    }

    public function updateAction(string $id, PatternEntryDto $patternEntryDto): ResponseInterface
    {
        try {
            $this->fileArrayPatternBackend->append($patternEntryDto->toPatternEntry($id));
            $this->addFlashMessage($this->translateLabel('flash.pattern.updated'));
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($this->translateValidationError($invalidArgumentException), $this->translateLabel('flash.title.validationError'), ContextualFeedbackSeverity::ERROR);
            return $this->redirect('overview', null, null, ['editId' => $id]);
        }

        return $this->redirect('overview');
    }

    public function deleteAction(string $id): ResponseInterface
    {
        $this->fileArrayPatternBackend->removeById($id);
        $this->addFlashMessage($this->translateLabel('flash.pattern.deleted'));
        return $this->redirect('overview');
    }

    public function pruneAction(): ResponseInterface
    {
        $this->fileArrayPatternBackend->pruneExpired();
        $this->addFlashMessage($this->translateLabel('flash.pattern.pruned'));
        return $this->redirect('overview');
    }

    public function bansAction(string $search = ''): ResponseInterface
    {
        $search = trim($search);
        $moduleTemplate = $this->firewallModuleTemplateFactory->create($this->request, 'bans');

        $banGroups = [];
        $totalBans = 0;
        foreach ($this->collectRulesByBanType() as [$banType, $ruleName]) {
            $bans = $this->filterBans($this->config->banManager()->listBans($ruleName, $banType), $search);
            if ($bans === []) {
                continue;
            }

            $banGroups[] = [
                'rule' => $ruleName,
                'type' => $banType->value,
                'bans' => $this->formatBans($bans),
            ];
            $totalBans += count($bans);
        }

        $moduleTemplate->assignMultiple([
            'banGroups' => $banGroups,
            'totalBans' => $totalBans,
            'search' => $search,
            'usesInMemoryStore' => $this->config->cache instanceof InMemoryCache,
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Bans');
    }

    /**
     * @param array<mixed> $types
     * @param array<mixed> $excludeKeys
     */
    public function eventsAction(array $types = [], string $search = '', string $key = '', string $rule = '', int $page = 1, string $operation = '', array $excludeKeys = [], string $range = ''): ResponseInterface
    {
        $rule = mb_substr(trim($rule), 0, 255);
        [$types, $search, $excludeKeys, $range] = $this->firewallModuleState->resolveEventFilters($this->request, $types, trim($search), $key, $rule, $operation, $excludeKeys, $range);
        $moduleTemplate = $this->firewallModuleTemplateFactory->create($this->request, 'events');
        $moduleTemplate->assignMultiple($this->eventLogViewDataProvider->getViewData($types, $search, $key, $rule, $page, $excludeKeys, $range));

        return $moduleTemplate->renderResponse('Backend/Firewall/Events');
    }

    /**
     * Create an exact ip pattern entry for the address an event row
     * displays. The posted address must be the row's complete key: its
     * keyed hash has to match the posted key hash, which rejects anonymized
     * network addresses and non-IP values.
     */
    public function blockKeyAction(string $ip, string $key): ResponseInterface
    {
        $patternEntry = $this->blockableKeyResolver->resolve($ip, $key);
        if (!$patternEntry instanceof PatternEntry) {
            $this->addFlashMessage($this->translateLabel('flash.key.blockNotPossible'), $this->translateLabel('flash.title.error'), ContextualFeedbackSeverity::ERROR);

            return $this->redirect('events');
        }

        try {
            $this->fileArrayPatternBackend->append($patternEntry);
            $this->addFlashMessage(sprintf($this->translateLabel('flash.key.blocked'), $patternEntry->kind->value, $patternEntry->value));
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($this->translateValidationError($invalidArgumentException), $this->translateLabel('flash.title.validationError'), ContextualFeedbackSeverity::ERROR);
        }

        return $this->redirect('events');
    }

    public function statisticsAction(string $range = ''): ResponseInterface
    {
        $moduleTemplate = $this->firewallModuleTemplateFactory->create($this->request, 'statistics');
        $moduleTemplate->assignMultiple($this->statisticsViewDataProvider->getViewData($this->firewallModuleState->resolveStatisticsRange($this->request, $range)));

        return $moduleTemplate->renderResponse('Backend/Firewall/Statistics');
    }

    /**
     * @return list<array{0: BanType, 1: string}>
     */
    private function collectRulesByBanType(): array
    {
        $rulesByBanType = [];
        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $rulesByBanType[] = [BanType::Allow2Ban, $allow2BanRule->name()];
        }

        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $rulesByBanType[] = [BanType::Fail2Ban, $fail2BanRule->name()];
        }

        return $rulesByBanType;
    }

    /**
     * @param list<array{key: string, expiresAt: float}> $bans
     * @return list<array{key: string, expiresAt: float}>
     */
    private function filterBans(array $bans, string $search): array
    {
        if ($search === '') {
            return $bans;
        }

        return array_values(array_filter(
            $bans,
            static fn(array $ban): bool => stripos($ban['key'], $search) !== false
        ));
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
     * @return list<array{key: string, expiresAt: int, expiresInLabel: string}>
     */
    private function formatBans(array $bans): array
    {
        usort($bans, static fn(array $left, array $right): int => $left['expiresAt'] <=> $right['expiresAt']);
        $now = time();

        return array_map(
            fn(array $ban): array => [
                'key' => $ban['key'],
                'expiresAt' => (int)$ban['expiresAt'],
                'expiresInLabel' => $this->formatRemainingTime((int)$ban['expiresAt'] - $now),
            ],
            $bans,
        );
    }

    private function formatRemainingTime(int $seconds): string
    {
        if ($seconds <= 0) {
            return $this->translateLabel('bans.remaining.expired');
        }

        if ($seconds < 60) {
            return sprintf($this->translateLabel('bans.remaining.seconds'), $seconds);
        }

        if ($seconds < 3600) {
            return sprintf($this->translateLabel('bans.remaining.minutes'), intdiv($seconds, 60));
        }

        if ($seconds < 86400) {
            return sprintf($this->translateLabel('bans.remaining.hoursMinutes'), intdiv($seconds, 3600), intdiv($seconds % 3600, 60));
        }

        return sprintf($this->translateLabel('bans.remaining.daysHours'), intdiv($seconds, 86400), intdiv($seconds % 86400, 3600));
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findPatternById(string $id): ?array
    {
        $patterns = $this->fileArrayPatternBackend->listRaw();
        foreach ($patterns as $pattern) {
            if (($pattern['id'] ?? null) === $id) {
                return $pattern;
            }
        }

        return null;
    }
}
