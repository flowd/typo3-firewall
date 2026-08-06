<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Reports;

use Flowd\Typo3Firewall\Reports\PcreJitStatusProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Reports\Status;

#[CoversClass(PcreJitStatusProvider::class)]
final class PcreJitStatusProviderTest extends TestCase
{
    protected function setUp(): void
    {
        $languageService = $this->createMock(LanguageService::class);
        $languageService->method('sL')->willReturnCallback(
            static fn(string $key): string => substr($key, (int)strrpos($key, ':') + 1),
        );
        $GLOBALS['LANG'] = $languageService;
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['LANG']);
    }

    #[Test]
    public function labelIsTranslated(): void
    {
        self::assertSame('reports.label', (new PcreJitStatusProvider())->getLabel());
    }

    #[Test]
    public function enabledJitReportsOk(): void
    {
        $status = $this->getPcreJitStatus(new PcreJitStatusProvider(jitSupported: true, jitEnabled: true));

        self::assertSame(ContextualFeedbackSeverity::OK, $status->getSeverity());
        self::assertSame('reports.pcreJit.enabled.value', $status->getValue());
        self::assertSame('', $status->getMessage());
    }

    #[Test]
    public function disabledJitReportsWarning(): void
    {
        $status = $this->getPcreJitStatus(new PcreJitStatusProvider(jitSupported: true, jitEnabled: false));

        self::assertSame(ContextualFeedbackSeverity::WARNING, $status->getSeverity());
        self::assertSame('reports.pcreJit.disabled.value', $status->getValue());
        self::assertSame('reports.pcreJit.disabled.message', $status->getMessage());
    }

    #[Test]
    public function unsupportedJitReportsWarning(): void
    {
        $status = $this->getPcreJitStatus(new PcreJitStatusProvider(jitSupported: false, jitEnabled: true));

        self::assertSame(ContextualFeedbackSeverity::WARNING, $status->getSeverity());
        self::assertSame('reports.pcreJit.unavailable.value', $status->getValue());
        self::assertSame('reports.pcreJit.unavailable.message', $status->getMessage());
    }

    #[Test]
    public function runtimeDefaultsProduceAStatus(): void
    {
        $status = $this->getPcreJitStatus(new PcreJitStatusProvider());

        self::assertSame('reports.pcreJit.title', $status->getTitle());
    }

    private function getPcreJitStatus(PcreJitStatusProvider $pcreJitStatusProvider): Status
    {
        $statusList = $pcreJitStatusProvider->getStatus();

        self::assertArrayHasKey('pcreJit', $statusList);
        return $statusList['pcreJit'];
    }
}
