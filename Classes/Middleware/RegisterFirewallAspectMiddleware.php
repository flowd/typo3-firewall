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
use TYPO3\CMS\Core\Utility\GeneralUtility;

final readonly class RegisterFirewallAspectMiddleware implements MiddlewareInterface
{
    public function __construct(private Context $context) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $this->context->setAspect(
            'firewall',
            GeneralUtility::makeInstance(
                FirewallAspect::class,
                $request->getAttribute(RequestContext::ATTRIBUTE_NAME)
            )
        );

        return $handler->handle($request);
    }
}
