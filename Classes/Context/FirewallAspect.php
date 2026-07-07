<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Context;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use TYPO3\CMS\Core\Context\AspectInterface;
use TYPO3\CMS\Core\Context\Exception\AspectPropertyNotFoundException;

/**
 * Exposes the firewall decision of the current request through the TYPO3
 * Context API. Registered by the RegisterFirewallAspectMiddleware.
 */
final readonly class FirewallAspect implements AspectInterface
{
    public function __construct(private RequestContext $requestContext) {}

    public function get(string $name): RequestContext|FirewallResult
    {
        return match ($name) {
            'context' => $this->requestContext,
            'result' => $this->requestContext->getResult(),
            default => throw new AspectPropertyNotFoundException(
                sprintf('Property "%s" not found in firewall aspect.', $name),
                1780065304
            ),
        };
    }

    /**
     * Report an application-level failure (e.g. a failed login) to a fail2ban
     * rule. Without a key the firewall derives the discriminator from the
     * rule's key extractor, falling back to the resolved client IP.
     */
    public function recordFailure(string $ruleName, ?string $key = null): void
    {
        $this->requestContext->recordFailure($ruleName, $key);
    }

    /**
     * Report a hit to an allow2ban rule, e.g. an expensive operation the
     * pre-handler path cannot see. Key resolution as in recordFailure().
     */
    public function recordHit(string $ruleName, ?string $key = null): void
    {
        $this->requestContext->recordHit($ruleName, $key);
    }
}
