<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Resolves whether a logged key is currently blocked by an active ban or a
 * blocklist pattern entry.
 *
 * The event log stores only the keyed hash of a key, so the lookup runs the
 * other way around: the clear-text keys of all active bans and the values of
 * ip pattern entries are hashed once and compared against the logged hash.
 * CIDR entries are evaluated against the readable key_display IP; when that
 * IP is an anonymized network address, only entries at least as coarse as
 * the anonymization mask (/24 for IPv4, /64 for IPv6) are decidable and
 * finer entries are skipped.
 */
final class KeyBlockStatusProvider
{
    /** @var array<string, KeyBlockStatus>|null */
    private ?array $banStatusByKeyHash = null;

    /** @var array<string, KeyBlockStatus>|null */
    private ?array $ipPatternStatusByKeyHash = null;

    /** @var list<PatternEntry>|null */
    private ?array $cidrPatternEntries = null;

    public function __construct(
        private readonly Config $config,
        private readonly KeyHasher $keyHasher,
        private readonly FileArrayPatternBackend $fileArrayPatternBackend,
    ) {}

    public function findBlockStatus(string $keyHash, string $keyDisplay): ?KeyBlockStatus
    {
        if ($keyHash === '') {
            return null;
        }

        return $this->getBanStatusByKeyHash()[$keyHash]
            ?? $this->getIpPatternStatusByKeyHash()[$keyHash]
            ?? $this->findCidrPatternStatus($keyDisplay, $keyHash);
    }

    /**
     * @return array<string, KeyBlockStatus>
     */
    private function getBanStatusByKeyHash(): array
    {
        if ($this->banStatusByKeyHash !== null) {
            return $this->banStatusByKeyHash;
        }

        $banManager = $this->config->banManager();
        $statuses = [];
        foreach ($this->collectRulesByBanType() as [$banType, $ruleName]) {
            foreach ($banManager->listBans($ruleName, $banType) as $ban) {
                $statuses[$this->keyHasher->hash($ban['key'])] = new KeyBlockStatus(
                    KeyBlockStatus::SOURCE_BAN,
                    sprintf('%s (%s)', $ruleName, $banType->value),
                );
            }
        }

        return $this->banStatusByKeyHash = $statuses;
    }

    /**
     * @return list<array{0: BanType, 1: string}>
     */
    private function collectRulesByBanType(): array
    {
        $rulesByBanType = [];
        foreach ($this->config->allow2ban->rules() as $allow2BanRule) {
            $rulesByBanType[] = [BanType::Allow2Ban, $allow2BanRule->name()];
        }

        foreach ($this->config->fail2ban->rules() as $fail2BanRule) {
            $rulesByBanType[] = [BanType::Fail2Ban, $fail2BanRule->name()];
        }

        return $rulesByBanType;
    }

    /**
     * @return array<string, KeyBlockStatus>
     */
    private function getIpPatternStatusByKeyHash(): array
    {
        if ($this->ipPatternStatusByKeyHash !== null) {
            return $this->ipPatternStatusByKeyHash;
        }

        $this->loadPatternEntries();

        return $this->ipPatternStatusByKeyHash ?? [];
    }

    /**
     * @return list<PatternEntry>
     */
    private function getCidrPatternEntries(): array
    {
        if ($this->cidrPatternEntries !== null) {
            return $this->cidrPatternEntries;
        }

        $this->loadPatternEntries();

        return $this->cidrPatternEntries ?? [];
    }

    private function loadPatternEntries(): void
    {
        $ipStatuses = [];
        $cidrEntries = [];
        foreach ($this->fileArrayPatternBackend->consume()->entries as $patternEntry) {
            if ($patternEntry->kind === PatternKind::IP) {
                $ipStatuses[$this->keyHasher->hash($patternEntry->value)] = new KeyBlockStatus(
                    KeyBlockStatus::SOURCE_PATTERN,
                    sprintf('%s %s', $patternEntry->kind->value, $patternEntry->value),
                );
            }

            if ($patternEntry->kind === PatternKind::CIDR) {
                $cidrEntries[] = $patternEntry;
            }
        }

        $this->ipPatternStatusByKeyHash = $ipStatuses;
        $this->cidrPatternEntries = $cidrEntries;
    }

    private function findCidrPatternStatus(string $keyDisplay, string $keyHash): ?KeyBlockStatus
    {
        if (!GeneralUtility::validIP($keyDisplay)) {
            return null;
        }

        // A display whose keyed hash matches the stored hash is the complete
        // key; everything else is an anonymized network address.
        $isAnonymized = $this->keyHasher->hash($keyDisplay) !== $keyHash;
        foreach ($this->getCidrPatternEntries() as $patternEntry) {
            if ($isAnonymized && !$this->isCoarserThanAnonymizationMask($patternEntry->value)) {
                continue;
            }

            if (GeneralUtility::cmpIP($keyDisplay, $patternEntry->value)) {
                return new KeyBlockStatus(
                    KeyBlockStatus::SOURCE_PATTERN,
                    sprintf('%s %s', $patternEntry->kind->value, $patternEntry->value),
                );
            }
        }

        return null;
    }

    /**
     * Whether the CIDR prefix is at least as coarse as the anonymization mask,
     * so an anonymized network address still decides the match for every real
     * client IP behind it.
     */
    private function isCoarserThanAnonymizationMask(string $cidr): bool
    {
        [$network, $prefix] = array_pad(explode('/', $cidr, 2), 2, null);
        if (!is_string($network) || !is_numeric($prefix)) {
            return false;
        }

        $anonymizationBits = GeneralUtility::validIPv4($network) ? 24 : 64;

        return (int)$prefix <= $anonymizationBits;
    }
}
