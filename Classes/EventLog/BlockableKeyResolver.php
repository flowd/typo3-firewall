<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Derives the pattern entry that blocks a logged key.
 *
 * A readable IP resolves to an exact ip entry only when it provably is the
 * complete key: its keyed hash must match the stored key hash. Anonymized
 * network addresses fail that comparison - their real client IP is unknown
 * and must not be blocked - and so do keys stored as hash only.
 */
final class BlockableKeyResolver
{
    public function __construct(
        private readonly KeyHasher $keyHasher,
    ) {}

    public function resolve(string $keyDisplay, string $keyHash): ?PatternEntry
    {
        if (!GeneralUtility::validIP($keyDisplay)) {
            return null;
        }

        if ($keyHash === '' || $this->keyHasher->hash($keyDisplay) !== $keyHash) {
            return null;
        }

        return new PatternEntry(PatternKind::IP, $keyDisplay);
    }
}
