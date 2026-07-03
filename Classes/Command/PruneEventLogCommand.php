<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Command;

use Flowd\Typo3Firewall\EventLog\EventLogger;
use Flowd\Typo3Firewall\EventLog\EventLogSettings;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Deletes firewall event log entries older than the configured retention.
 */
#[AsCommand(
    name: 'firewall:eventlog:prune',
    description: 'Delete firewall event log entries older than the configured retention',
)]
final class PruneEventLogCommand extends Command
{
    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly EventLogSettings $eventLogSettings,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption(
            'days',
            null,
            InputOption::VALUE_REQUIRED,
            'Delete entries older than this many days. Defaults to the retention configured in the extension settings.'
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $symfonyStyle = new SymfonyStyle($input, $output);

        $daysOption = $input->getOption('days');
        $days = is_numeric($daysOption)
            ? max(1, (int)$daysOption)
            : $this->eventLogSettings->getRetentionDays();
        $deleteBefore = time() - $days * 86400;

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(EventLogger::TABLE_NAME);
        $deletedRows = $queryBuilder
            ->delete(EventLogger::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->lt('created_at', $queryBuilder->createNamedParameter($deleteBefore, Connection::PARAM_INT))
            )
            ->executeStatement();

        $symfonyStyle->success(sprintf('Deleted %d firewall event log entries older than %d days.', $deletedRows, $days));

        return Command::SUCCESS;
    }
}
