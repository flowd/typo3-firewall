<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Form\Finisher;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Typo3Firewall\Configuration\ExtensionConfiguration;
use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Extbase\Mvc\Request;
use TYPO3\CMS\Form\Domain\Finishers\AbstractFinisher;

/**
 * Reports every successful form submission to the firewall as a fail2ban
 * signal. Unlike honeypot/CAPTCHA (bot-only), this counts *all* submissions,
 * so it also catches real visitors hammering a form.
 *
 * The counting and banning is done by phirewall: once the configured fail2ban
 * rule reaches its threshold within the period, the client is banned and the
 * firewall middleware rejects further requests early — before TYPO3 fully boots.
 *
 * Opt-in by rule: this finisher is inert until a fail2ban rule with the
 * configured name (default "form-flood") exists in the phirewall configuration.
 * recordFailure() on an unknown rule name is a no-op, so without the rule
 * nothing happens.
 *
 * @see \Flowd\Phirewall\Context\RequestContext::recordFailure()
 */
final class FloodProtectionFinisher extends AbstractFinisher
{
    public const string DEFAULT_RULE_IDENTIFIER = 'form-flood';

    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    protected function executeInternal(): void
    {
        if (!$this->extensionConfiguration->formFloodingProtection->enabled) {
            return;
        }

        $request = $this->finisherContext->getRequest();
        $requestContext = $request->getAttribute(RequestContext::ATTRIBUTE_NAME);
        if (!$requestContext instanceof RequestContext) {
            // Firewall middleware did not run (e.g. firewall disabled).
            return;
        }

        $floodProtectionFinisherTriggered = new FloodProtectionFinisherTriggered(self::DEFAULT_RULE_IDENTIFIER);
        $this->eventDispatcher->dispatch($floodProtectionFinisherTriggered);

        $rule = trim($floodProtectionFinisherTriggered->ruleIdentifier);
        if ($rule === '') {
            return;
        }

        $requestContext->recordFailure($rule, $this->resolveClientIp($request));
    }

    private function resolveClientIp(Request $serverRequest): string
    {
        $normalizedParams = $serverRequest->getAttribute('normalizedParams');

        return $normalizedParams instanceof NormalizedParams
            ? $normalizedParams->getRemoteAddress()
            : 'unknown';
    }
}
