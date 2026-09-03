<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Reports;

use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Flowd\Typo3Firewall\Reports\FullIpLoggingStatusProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Reports\Status;

#[CoversClass(FullIpLoggingStatusProvider::class)]
final class FullIpLoggingStatusProviderTest extends TestCase
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
        self::assertSame('reports.label', $this->createProvider('')->getLabel());
    }

    #[Test]
    public function anEmptyRuleListReportsOk(): void
    {
        $status = $this->getFullIpLoggingStatus($this->createProvider(''));

        self::assertSame(ContextualFeedbackSeverity::OK, $status->getSeverity());
        self::assertSame('reports.fullIpLogging.inactive.value', $status->getValue());
    }

    #[Test]
    public function configuredRulesReportAWarningListingThem(): void
    {
        $status = $this->getFullIpLoggingStatus($this->createProvider('login-brute-force, scanner-paths'));

        self::assertSame(ContextualFeedbackSeverity::WARNING, $status->getSeverity());
        self::assertSame('login-brute-force, scanner-paths', $status->getValue());
        self::assertSame('reports.fullIpLogging.active.message', $status->getMessage());
    }

    private function createProvider(string $fullIpRules): FullIpLoggingStatusProvider
    {
        $extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $extensionConfiguration->method('get')->willReturnCallback(
            static function (string $extension, string $path) use ($fullIpRules): string {
                if ($path !== 'eventLogFullIpRules') {
                    throw new \RuntimeException('Setting not configured: ' . $path, 1770000002);
                }

                return $fullIpRules;
            }
        );

        return new FullIpLoggingStatusProvider(new EventLogSettings($extensionConfiguration));
    }

    private function getFullIpLoggingStatus(FullIpLoggingStatusProvider $fullIpLoggingStatusProvider): Status
    {
        $statuses = $fullIpLoggingStatusProvider->getStatus();

        self::assertArrayHasKey('fullIpLogging', $statuses);

        return $statuses['fullIpLogging'];
    }
}
