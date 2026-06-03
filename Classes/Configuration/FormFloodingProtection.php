<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Configuration;

/**
 * @phpstan-type FloodingSettings array{
 *     enable?: bool|int|string,
 *     threshold?: int|string,
 *     period?: int|string,
 *     ban?: int|string
 * }
 */
final readonly class FormFloodingProtection
{
    public function __construct(
        // Opt-in: no fail2ban rule is registered unless explicitly enabled via .
        public bool $enabled = false,
        // Submissions allowed within $period before the client gets banned.
        public int $threshold = 5,
        // Sliding window in seconds over which submissions are counted.
        public int $period = 60,
        // Ban duration in seconds once the threshold is exceeded (1 hour).
        public int $ban = 3600,
    ) {}

    /**
     * @param FloodingSettings $array
     */
    public static function tryFrom(array $array): self
    {
        $defaults = new self();

        return new self(
            isset($array['enable']) ? (bool)(int)$array['enable'] : $defaults->enabled,
            self::intOrDefault($array['threshold'] ?? null, $defaults->threshold),
            self::intOrDefault($array['period'] ?? null, $defaults->period),
            self::intOrDefault($array['ban'] ?? null, $defaults->ban),
        );
    }

    private static function intOrDefault(mixed $value, int $default): int
    {
        return is_numeric($value) ? (int)$value : $default;
    }
}
