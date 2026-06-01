<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Context;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\FirewallResult;
use TYPO3\CMS\Core\Context\AspectInterface;
use TYPO3\CMS\Core\Context\Exception\AspectPropertyNotFoundException;

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
            )
        };
    }

    public function recordFailure(string $ruleName, string $key): void
    {
        $this->requestContext->recordFailure($ruleName, $key);
    }
}
