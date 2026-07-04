<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\IpAnonymizationUtility;

/**
 * Writes firewall events to the tx_firewall_event table.
 *
 * A logging failure must never break request handling, so every database
 * error is caught and only reported to the logger.
 */
final class EventLogger
{
    public const string TABLE_NAME = 'tx_firewall_event';

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly EventLogSettings $eventLogSettings,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @param array<string, int|string|null> $meta
     */
    public function log(
        FirewallEventType $firewallEventType,
        ServerRequestInterface $serverRequest,
        string $rule = '',
        ?string $key = null,
        string $banType = '',
        array $meta = [],
    ): void {
        if (!$this->eventLogSettings->isEnabled() || !$this->eventLogSettings->isTypeEnabled($firewallEventType)) {
            return;
        }

        $key ??= $this->resolveClientIp();

        try {
            $this->connectionPool->getConnectionForTable(self::TABLE_NAME)->insert(self::TABLE_NAME, [
                'event_type' => $firewallEventType->value,
                'rule' => mb_substr($rule, 0, 255),
                'ban_type' => mb_substr($banType, 0, 16),
                'key_hash' => $key === '' ? '' : hash('sha256', $key),
                'key_display' => $this->buildKeyDisplay($key),
                'request_host' => mb_substr($serverRequest->getUri()->getHost(), 0, 255),
                'request_path' => mb_substr($serverRequest->getUri()->getPath(), 0, 2048),
                'request_method' => mb_substr($serverRequest->getMethod(), 0, 10),
                'user_agent' => mb_substr($serverRequest->getHeaderLine('User-Agent'), 0, 255),
                'meta' => json_encode(array_filter($meta, static fn(int|string|null $value): bool => $value !== null), JSON_THROW_ON_ERROR),
                'created_at' => time(),
            ]);
        } catch (\Throwable $throwable) {
            $this->logger?->error('Failed to write a firewall event log entry', [
                'eventType' => $firewallEventType->value,
                'exception' => $throwable,
            ]);
        }
    }

    /**
     * Only IP addresses are stored in readable form. Other keys may carry
     * sensitive values (header or session based keys), so they are stored
     * as hash only.
     */
    private function buildKeyDisplay(string $key): string
    {
        if (filter_var($key, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        if (!$this->eventLogSettings->isIpAnonymizationEnabled()) {
            return $key;
        }

        return IpAnonymizationUtility::anonymizeIp($key, 1);
    }

    private function resolveClientIp(): string
    {
        $remoteAddress = GeneralUtility::getIndpEnv('REMOTE_ADDR');

        return is_string($remoteAddress) ? $remoteAddress : '';
    }
}
