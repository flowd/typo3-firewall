<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Reports;

use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Reports\Status;
use TYPO3\CMS\Reports\StatusProviderInterface;

/**
 * Reports whether PCRE JIT is available and enabled. The firewall evaluates
 * regular expression patterns on every request, so matching without JIT is
 * noticeably slower.
 */
final class PcreJitStatusProvider implements StatusProviderInterface
{
    private const string LANGUAGE_FILE = 'LLL:EXT:firewall/Resources/Private/Language/locallang.xlf';

    /**
     * The flags default to the runtime environment; tests pass them explicitly.
     */
    public function __construct(
        private readonly ?bool $jitSupported = null,
        private readonly ?bool $jitEnabled = null,
    ) {}

    /**
     * @return Status[]
     */
    public function getStatus(): array
    {
        return ['pcreJit' => $this->createPcreJitStatus()];
    }

    public function getLabel(): string
    {
        return $this->translate('reports.label');
    }

    private function createPcreJitStatus(): Status
    {
        $title = $this->translate('reports.pcreJit.title');

        if (!($this->jitSupported ?? PCRE_JIT_SUPPORT)) {
            return new Status(
                $title,
                $this->translate('reports.pcreJit.unavailable.value'),
                $this->translate('reports.pcreJit.unavailable.message'),
                ContextualFeedbackSeverity::WARNING,
            );
        }

        if (!($this->jitEnabled ?? filter_var(ini_get('pcre.jit'), FILTER_VALIDATE_BOOL))) {
            return new Status(
                $title,
                $this->translate('reports.pcreJit.disabled.value'),
                $this->translate('reports.pcreJit.disabled.message'),
                ContextualFeedbackSeverity::WARNING,
            );
        }

        return new Status(
            $title,
            $this->translate('reports.pcreJit.enabled.value'),
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
