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

readonly class RegisterFirewallAspectMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $firewall = GeneralUtility::makeInstance(
            FirewallAspect::class,
            $request->getAttribute(RequestContext::ATTRIBUTE_NAME)
        );
        $context = GeneralUtility::makeInstance(Context::class);
        $context->setAspect('firewall', $firewall);

        return $handler->handle($request);
    }
}
