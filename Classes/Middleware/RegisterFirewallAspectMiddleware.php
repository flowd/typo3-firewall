<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Middleware;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Typo3Firewall\Context\FirewallAspect;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Context\Context;

/**
 * Registers the "firewall" Context aspect, see the Middleware chapter of
 * the manual.
 */
final readonly class RegisterFirewallAspectMiddleware implements MiddlewareInterface
{
    public function __construct(private Context $context) {}

    public function process(ServerRequestInterface $serverRequest, RequestHandlerInterface $requestHandler): ResponseInterface
    {
        $requestContext = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);

        // Without the firewall middleware there is no decision to expose.
        if ($requestContext instanceof RequestContext) {
            $this->context->setAspect('firewall', new FirewallAspect($requestContext));
        }

        return $requestHandler->handle($serverRequest);
    }
}
