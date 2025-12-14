<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Dto;

use Flowd\Phirewall\Pattern\PatternEntry;

class PatternEntryDto
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
        public array $metadata = []
    ) {}

    public function toPatternEntry(): PatternEntry
    {
        $expiresAt = null;
        if (($this->expiresAt ?? '') !== '') {
            $expiresAt = strtotime((string)$this->expiresAt);
            if ($expiresAt === false) {
                $expiresAt = null;
            }
        }

        return new PatternEntry(
            kind: $this->kind,
            value: $this->value,
            target: $this->target,
            expiresAt: $expiresAt,
            addedAt: $this->addedAt,
            metadata: $this->metadata
        );
    }
}
