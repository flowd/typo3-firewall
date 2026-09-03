<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\EventLog;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\IpAnonymizationUtility;

/**
 * Derives the pattern entry that blocks a logged key.
 *
 * Only a full readable IP resolves, to an exact ip entry. An address equal
 * to its own anonymized form is an anonymized network address whose real
 * client IP is unknown, so it must not be blocked - and neither can keys
 * stored as hash only. Both resolve to null.
 */
final class BlockableKeyResolver
{
    public function resolve(string $keyDisplay): ?PatternEntry
    {
        if (!GeneralUtility::validIP($keyDisplay)) {
            return null;
        }

        if (IpAnonymizationUtility::anonymizeIp($keyDisplay, 1) === $keyDisplay) {
            return null;
        }

        return new PatternEntry(PatternKind::IP, $keyDisplay);
    }
}
