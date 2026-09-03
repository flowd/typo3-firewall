<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Reports;

use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Reports\Status;
use TYPO3\CMS\Reports\StatusProviderInterface;

/**
 * Warns while the event log stores unanonymized client IPs for some rules.
 * That exception is meant for the duration of an attack analysis; the
 * warning keeps it from being forgotten afterwards.
 */
final class FullIpLoggingStatusProvider implements StatusProviderInterface
{
    private const string LANGUAGE_FILE = 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf';

    public function __construct(
        private readonly EventLogSettings $eventLogSettings,
    ) {}

    /**
     * @return Status[]
     */
    public function getStatus(): array
    {
        return ['fullIpLogging' => $this->createFullIpLoggingStatus()];
    }

    public function getLabel(): string
    {
        return $this->translate('reports.label');
    }

    private function createFullIpLoggingStatus(): Status
    {
        $title = $this->translate('reports.fullIpLogging.title');
        $fullIpLoggingRules = $this->eventLogSettings->getFullIpLoggingRules();

        if ($fullIpLoggingRules === []) {
            return new Status(
                $title,
                $this->translate('reports.fullIpLogging.inactive.value'),
            );
        }

        return new Status(
            $title,
            implode(', ', $fullIpLoggingRules),
            $this->translate('reports.fullIpLogging.active.message'),
            ContextualFeedbackSeverity::WARNING,
        );
    }

    private function translate(string $key): string
    {
        return $this->getLanguageService()->sL(self::LANGUAGE_FILE . ':' . $key);
    }

    private function getLanguageService(): LanguageService
    {
        /** @var LanguageService $languageService */
        $languageService = $GLOBALS['LANG'];
        return $languageService;
    }
}
