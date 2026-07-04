<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Pattern;

/**
 * Validation error for pattern input that carries the rejected value,
 * so the backend module can render a localized message with it.
 */
final class PatternValidationException extends \InvalidArgumentException
{
    public function __construct(
        string $message,
        int $code,
        private readonly string $invalidValue = '',
    ) {
        parent::__construct($message, $code);
    }

    public function getInvalidValue(): string
    {
        return $this->invalidValue;
    }
}
