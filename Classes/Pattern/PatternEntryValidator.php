<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

/**
 * Validates a PatternEntry before it is persisted by FileArrayPatternBackend.
 *
 * @internal
 */
final class PatternEntryValidator
{
    /**
     * @throws \InvalidArgumentException If the pattern is invalid
     */
    public function validate(PatternEntry $patternEntry): void
    {
        $this->validateNotEmpty($patternEntry);
        $this->validateTargetByKind($patternEntry);
        $this->validateValueByKind($patternEntry);
    }

    private function validateNotEmpty(PatternEntry $patternEntry): void
    {
        if ($patternEntry->value === '') {
            throw new \InvalidArgumentException(
                'Pattern value must not be empty',
                1770244701
            );
        }
    }

    private function validateTargetByKind(PatternEntry $patternEntry): void
    {
        if (!in_array($patternEntry->kind, [PatternKind::HEADER_EXACT, PatternKind::HEADER_REGEX], true)) {
            return;
        }

        if ($patternEntry->target === null || trim($patternEntry->target) === '') {
            throw new \InvalidArgumentException(
                sprintf('Pattern kind "%s" requires the target field to contain the header name', $patternEntry->kind->value),
                1779136101
            );
        }
    }

    private function validateValueByKind(PatternEntry $patternEntry): void
    {
        match ($patternEntry->kind) {
            PatternKind::IP => $this->validateIpAddress($patternEntry->value),
            PatternKind::CIDR => $this->validateCidr($patternEntry->value),
            PatternKind::PATH_REGEX, PatternKind::HEADER_REGEX, PatternKind::REQUEST_REGEX => $this->validateRegex($patternEntry->value),
            default => null,
        };
    }

    private function validateIpAddress(string $value): void
    {
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException(
                sprintf('Invalid IP address: %s', $value),
                1770244710
            );
        }
    }

    private function validateCidr(string $value): void
    {
        if (!$this->isValidCidr($value)) {
            throw new \InvalidArgumentException(
                sprintf('Invalid CIDR notation: %s', $value),
                1770244715
            );
        }
    }

    private function validateRegex(string $value): void
    {
        if (@preg_match($value, '') === false) {
            throw new \InvalidArgumentException(
                sprintf('Invalid regex pattern: %s', $value),
                1770244720
            );
        }
    }

    private function isValidCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2) {
            return false;
        }

        [$ip, $prefix] = $parts;

        return $this->isValidCidrPrefix($ip, $prefix);
    }

    private function isValidCidrPrefix(string $ip, string $prefix): bool
    {
        if (!is_numeric($prefix)) {
            return false;
        }

        $prefixInt = (int)$prefix;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $prefixInt >= 0 && $prefixInt <= 32;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $prefixInt >= 0 && $prefixInt <= 128;
        }

        return false;
    }
}
