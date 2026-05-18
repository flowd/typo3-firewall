<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Dto;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;

/**
 * Data transfer object for pattern entry form submissions.
 *
 * Only fields that are user-editable via the backend form are exposed. Timestamps
 * (addedAt, lastModifiedAt) and identity (id) are managed by the backend itself
 * and intentionally not mappable from the request to prevent mass-assignment.
 */
final class PatternEntryDto
{
    public function __construct(
        public string $kind = '',
        public string $value = '',
        public ?string $target = null,
        public ?string $expiresAt = null,
    ) {}

    public function toPatternEntry(): PatternEntry
    {
        $kind = PatternKind::tryFrom(trim($this->kind));
        if ($kind === null) {
            throw new \InvalidArgumentException(
                sprintf('Invalid pattern kind: %s', $this->kind),
                1779107801
            );
        }

        return new PatternEntry(
            kind: $kind,
            value: trim($this->value),
            target: $this->target !== null ? trim($this->target) : null,
            expiresAt: $this->parseExpiresAt(),
        );
    }

    private function parseExpiresAt(): ?int
    {
        if ($this->expiresAt === null || trim($this->expiresAt) === '') {
            return null;
        }

        $value = trim($this->expiresAt);
        $timestamp = strtotime($value);
        if ($timestamp === false) {
            throw new \InvalidArgumentException(
                sprintf('Invalid expiration date: %s', $value),
                1779107802
            );
        }

        if ($timestamp <= time()) {
            throw new \InvalidArgumentException(
                sprintf('Expiration date must be in the future: %s', $value),
                1779107803
            );
        }

        return $timestamp;
    }
}
