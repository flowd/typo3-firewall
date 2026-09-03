<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

use Psr\Log\LoggerInterface;

/**
 * Builds the file backed pattern backend for the configured pattern file, so
 * every consumer reads and writes the same file the firewall matches against.
 */
final class PatternBackendFactory
{
    public function __construct(
        private readonly PatternStorageSettings $patternStorageSettings,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function create(): FileArrayPatternBackend
    {
        return FileArrayPatternBackend::forFile(
            $this->patternStorageSettings->getPatternsFilePath(),
            $this->logger,
        );
    }
}
