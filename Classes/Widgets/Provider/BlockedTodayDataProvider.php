<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Widgets\Provider;

use Flowd\Typo3Firewall\Statistics\EventStatisticsRepository;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconDataProviderInterface;

/**
 * Number of distinct attackers blocked since the start of the day,
 * shown in the "Blocked today" dashboard widget.
 */
final class BlockedTodayDataProvider implements NumberWithIconDataProviderInterface
{
    public function __construct(
        private readonly EventStatisticsRepository $eventStatisticsRepository,
    ) {}

    public function getNumber(): int
    {
        $startOfToday = (new \DateTimeImmutable('today'))->getTimestamp();

        return $this->eventStatisticsRepository->countDistinctBlockedKeysSince($startOfToday);
    }
}
