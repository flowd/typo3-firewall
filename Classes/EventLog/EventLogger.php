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

    /** Parameter names containing one of these markers are masked in the log. */
    private const array SENSITIVE_PARAMETER_MARKERS = ['pass', 'pwd', 'secret', 'token', 'otp', 'userident', 'credential', 'apikey', 'api_key', 'api-key', 'auth', 'jwt', 'bearer', 'session', 'csrf', 'signature'];

    private const int MAX_PARAMETERS_PER_LEVEL = 20;

    private const int MAX_PARAMETER_VALUE_LENGTH = 256;

    private const int MAX_PARAMETER_NAME_LENGTH = 64;

    private const int MAX_PARAMETER_DEPTH = 2;

    /** Keeps the encoded meta below the 64 KB TEXT column so the insert never fails on it. */
    private const int MAX_META_BYTES = 60000;

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly EventLogSettings $eventLogSettings,
        private readonly KeyHasher $keyHasher,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @param array<string, int|string|array<string, mixed>|null> $meta
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
        $meta = [...$meta, ...$this->postParametersMeta($serverRequest)];

        try {
            $this->connectionPool->getConnectionForTable(self::TABLE_NAME)->insert(self::TABLE_NAME, [
                'event_type' => $firewallEventType->value,
                'rule' => mb_substr($rule, 0, 255),
                'ban_type' => mb_substr($banType, 0, 16),
                'key_hash' => $key === '' ? '' : $this->keyHasher->hash($key),
                'key_display' => $this->buildKeyDisplay($key),
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
     * @param array<string, int|string|array<string, mixed>|null> $meta
     */
    private function encodeMeta(array $meta): string
    {
        $encodedMeta = json_encode(
            array_filter($meta, static fn(int|string|array|null $value): bool => $value !== null && $value !== []),
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
     * @return array{post?: array<string, mixed>}
     */
    private function postParametersMeta(ServerRequestInterface $serverRequest): array
    {
        $parsedBody = $serverRequest->getParsedBody();
        if (!is_array($parsedBody) || $parsedBody === []) {
            return [];
        }

        return ['post' => $this->sanitizeRequestParameters($parsedBody, $this->eventLogSettings->isParameterMaskingEnabled())];
    }

    /**
     * Bounded copy of request parameters for the event meta: values are
     * masked down to their first and last two characters (clear text but
     * truncated when masking is disabled), names that look like credentials
     * are masked completely either way, and large arrays are truncated.
     *
     * @param array<mixed> $parameters
     * @return array<string, mixed>
     */
    private function sanitizeRequestParameters(array $parameters, bool $maskValues, int $depth = 0): array
    {
        $sanitized = [];
        foreach (array_slice($parameters, 0, self::MAX_PARAMETERS_PER_LEVEL, true) as $name => $value) {
            $name = mb_substr((string)$name, 0, self::MAX_PARAMETER_NAME_LENGTH);
            $sanitized[$name] = $this->isSensitiveParameterName($name) ? '***' : $this->sanitizeParameterValue($value, $maskValues, $depth);
        }

        $skippedCount = count($parameters) - self::MAX_PARAMETERS_PER_LEVEL;
        if ($skippedCount > 0) {
            $sanitized['_skipped'] = sprintf('%d more parameters', $skippedCount);
        }

        return $sanitized;
    }

    /**
     * @return array<string, mixed>|string
     */
    private function sanitizeParameterValue(mixed $value, bool $maskValues, int $depth): array|string
    {
        if (is_array($value)) {
            return $depth < self::MAX_PARAMETER_DEPTH ? $this->sanitizeRequestParameters($value, $maskValues, $depth + 1) : '[...]';
        }

        if (!is_scalar($value)) {
            return get_debug_type($value);
        }

        $value = (string)$value;

        return $maskValues ? $this->maskParameterValue($value) : mb_substr($value, 0, self::MAX_PARAMETER_VALUE_LENGTH);
    }

    /**
     * Keeps the first and last two characters; values too short to keep
     * anything hidden are masked completely.
     */
    private function maskParameterValue(string $value): string
    {
        if (mb_strlen($value) <= 4) {
            return '***';
        }

        return mb_substr($value, 0, 2) . '***' . mb_substr($value, -2);
    }

    private function isSensitiveParameterName(string $name): bool
    {
        $normalizedName = strtolower($name);
        foreach (self::SENSITIVE_PARAMETER_MARKERS as $marker) {
            if (str_contains($normalizedName, $marker)) {
                return true;
            }
        }

        return false;
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
