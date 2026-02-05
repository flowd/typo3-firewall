<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Dto;

use Flowd\Phirewall\Pattern\PatternEntry;

/**
 * Data transfer object for pattern entry form submissions.
 */
final class PatternEntryDto
{
    /**
     * @param array<string, bool|float|int|string> $metadata
     */
    public function __construct(
        public string $kind = '',
        public string $value = '',
        public ?string $target = null,
        public ?string $expiresAt = null,
        public ?int $addedAt = null,
        public ?int $lastModifiedAt = null,
        public array $metadata = [],
    ) {}

    public function toPatternEntry(): PatternEntry
    {
        $metadata = $this->metadata;
        if ($this->lastModifiedAt !== null) {
            $metadata['lastModifiedAt'] = $this->lastModifiedAt;
        }

        return new PatternEntry(
            kind: trim($this->kind),
            value: trim($this->value),
            target: $this->target !== null ? trim($this->target) : null,
            expiresAt: $this->parseExpiresAt(),
            addedAt: $this->addedAt,
            metadata: $metadata,
        );
    }

    private function parseExpiresAt(): ?int
    {
        if ($this->expiresAt === null || trim($this->expiresAt) === '') {
            return null;
        }

        $timestamp = strtotime(trim($this->expiresAt));
        if ($timestamp === false) {
            return null;
        }

        // Ensure expiration is in the future
        if ($timestamp <= time()) {
            return null;
        }

        return $timestamp;
    }
}
