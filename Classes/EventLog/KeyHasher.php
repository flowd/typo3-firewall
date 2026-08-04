<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

/**
 * Keyed hash for event log client keys.
 *
 * A plain sha256 of an IPv4 address is reversible by enumerating the 2^32
 * address space, which would defeat the IP anonymization at the storage
 * layer. The HMAC with the installation's encryption key prevents that
 * while still allowing exact-key grouping and full-key search.
 */
final class KeyHasher
{
    public function hash(string $key): string
    {
        return hash_hmac('sha256', $key, $this->encryptionKey());
    }

    private function encryptionKey(): string
    {
        $systemConfiguration = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $sysSection = is_array($systemConfiguration) && is_array($systemConfiguration['SYS'] ?? null) ? $systemConfiguration['SYS'] : [];
        $encryptionKey = $sysSection['encryptionKey'] ?? null;

        return is_string($encryptionKey) ? $encryptionKey : '';
    }
}
