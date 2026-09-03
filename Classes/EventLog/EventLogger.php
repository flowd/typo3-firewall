<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\NormalizedParams;
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

    /** Keeps the encoded meta below the 64 KB TEXT column so the insert never fails on it. */
    private const int MAX_META_BYTES = 60000;

    /** Request headers whose values never reach the event log. */
    private const array REDACTED_HEADER_NAMES = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token'];

    private const string REDACTED_PLACEHOLDER = '[redacted]';

    private const int MAX_HEADER_VALUE_LENGTH = 512;

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly EventLogSettings $eventLogSettings,
        private readonly KeyHasher $keyHasher,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @param array<string, scalar|array<string, mixed>|null> $meta
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

        $key ??= $this->resolveClientIp($serverRequest);

        if ($this->eventLogSettings->isRequestHeaderLoggingEnabled()) {
            $meta['requestHeaders'] = $this->buildRequestHeaders($serverRequest);
        }

        try {
            $this->connectionPool->getConnectionForTable(self::TABLE_NAME)->insert(self::TABLE_NAME, [
                'event_type' => $firewallEventType->value,
                'rule' => mb_substr($rule, 0, 255),
                'ban_type' => mb_substr($banType, 0, 16),
                'key_hash' => $key === '' ? '' : $this->keyHasher->hash($key),
                'key_display' => $this->buildKeyDisplay($key, $rule),
                'request_host' => mb_substr($serverRequest->getUri()->getHost(), 0, 255),
                'request_path' => mb_substr($this->buildRequestTarget($serverRequest), 0, 2048),
                'request_method' => mb_substr($serverRequest->getMethod(), 0, 10),
                'user_agent' => mb_substr($serverRequest->getHeaderLine('User-Agent'), 0, 255),
                'meta' => $this->encodeMeta($meta),
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
     * Encode the meta array, replacing it with a marker entry when the
     * result would not fit the meta column; an oversized meta must never
     * make the insert fail, because that would drop the audit record.
     *
     * @param array<string, scalar|array<string, mixed>|null> $meta
     */
    private function encodeMeta(array $meta): string
    {
        $encodedMeta = json_encode(
            array_filter($meta, static fn(bool|int|float|string|array|null $value): bool => $value !== null && $value !== []),
            JSON_THROW_ON_ERROR
        );
        if (strlen($encodedMeta) > self::MAX_META_BYTES) {
            return json_encode(
                ['_truncated' => sprintf('meta of %d bytes exceeded the %d byte limit', strlen($encodedMeta), self::MAX_META_BYTES)],
                JSON_THROW_ON_ERROR
            );
        }

        return $encodedMeta;
    }

    /**
     * Path plus query string, like the request line of an access log.
     */
    private function buildRequestTarget(ServerRequestInterface $serverRequest): string
    {
        $uri = $serverRequest->getUri();
        $query = $uri->getQuery();

        return $uri->getPath() . ($query === '' ? '' : '?' . $query);
    }

    /**
     * Only IP addresses are stored in readable form. Other keys may carry
     * sensitive values (header or session based keys), so they are stored
     * as hash only. Rules on the full-IP list store the address
     * unanonymized, as a targeted exception while an attack is analyzed.
     */
    private function buildKeyDisplay(string $key, string $rule): string
    {
        if (!GeneralUtility::validIP($key)) {
            return '';
        }

        if (!$this->eventLogSettings->isIpAnonymizationEnabled() || $this->eventLogSettings->isFullIpLoggingEnabledForRule($rule)) {
            return $key;
        }

        return IpAnonymizationUtility::anonymizeIp($key, 1);
    }

    /**
     * The request headers as a meta fragment. They are read from the HTTP_*
     * server params - the environment as PHP received it - so upstream
     * normalization or manipulation of the PSR-7 request does not hide
     * anything; the PSR-7 headers are only the fallback for requests
     * without server params. Credential headers are redacted, the remaining
     * values are stripped of control characters and length bounded.
     *
     * @return array<string, string>
     */
    private function buildRequestHeaders(ServerRequestInterface $serverRequest): array
    {
        $headers = [];
        foreach ($this->extractServerParamHeaders($serverRequest->getServerParams()) as $name => $value) {
            $headers[$name] = $this->sanitizeHeaderValue($name, $value);
        }

        if ($headers !== []) {
            return $headers;
        }

        foreach ($serverRequest->getHeaders() as $name => $values) {
            $name = (string)$name;
            $headers[$name] = $this->sanitizeHeaderValue($name, implode(', ', $values));
        }

        return $headers;
    }

    /**
     * Header lines from the HTTP_* server params, plus the CONTENT_* pair
     * the SAPI exposes without the HTTP_ prefix; names are folded back to
     * the canonical Header-Case form.
     *
     * @param array<mixed> $serverParams
     * @return array<string, string>
     */
    private function extractServerParamHeaders(array $serverParams): array
    {
        $headers = [];
        foreach ($serverParams as $name => $value) {
            if (!is_string($name) || !is_scalar($value)) {
                continue;
            }

            if (str_starts_with($name, 'HTTP_')) {
                $headers[$this->buildHeaderName(substr($name, 5))] = (string)$value;
            } elseif ($name === 'CONTENT_TYPE' || $name === 'CONTENT_LENGTH') {
                $headers[$this->buildHeaderName($name)] = (string)$value;
            }
        }

        return $headers;
    }

    private function buildHeaderName(string $serverParamName): string
    {
        return ucwords(strtolower(str_replace('_', '-', $serverParamName)), '-');
    }

    private function sanitizeHeaderValue(string $name, string $value): string
    {
        if (in_array(strtolower($name), self::REDACTED_HEADER_NAMES, true)) {
            return self::REDACTED_PLACEHOLDER;
        }

        $value = (string)preg_replace('/[\x00-\x1F\x7F]/', ' ', $value);

        return mb_substr($value, 0, self::MAX_HEADER_VALUE_LENGTH);
    }

    /**
     * The client IP of the request; the normalized params apply TYPO3's
     * reverseProxyIP settings. For requests without the attribute they are
     * computed from the request.
     */
    private function resolveClientIp(ServerRequestInterface $serverRequest): string
    {
        $normalizedParams = $serverRequest->getAttribute('normalizedParams');
        if (!$normalizedParams instanceof NormalizedParams) {
            $normalizedParams = NormalizedParams::createFromRequest($serverRequest);
        }

        return $normalizedParams->getRemoteAddress();
    }
}
