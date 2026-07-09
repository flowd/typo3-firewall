<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Form\Finisher;

use Flowd\Phirewall\Context\RequestContext;
use Flowd\Typo3Firewall\Event\FloodProtectionFinisherTriggered;
use Flowd\Typo3Firewall\Form\FormFloodSettings;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Form\Domain\Finishers\AbstractFinisher;

/**
 * Reports every successfully validated submission of a form to the firewall
 * as an allow2ban signal, so a client that submits faster than the rule's
 * threshold gets banned. Unlike honeypot or CAPTCHA (bot-only), this also
 * catches real visitors hammering a form.
 *
 * By default it reports to the "form-flood" rule, so every form using the
 * finisher shares one counter per client. Set the "ruleIdentifier" finisher
 * option (in the form editor or the form definition) to report to a different
 * allow2ban rule instead, giving that form its own counter; the rule must be
 * defined in phirewall.php. The FloodProtectionFinisherTriggered event can
 * still override the identifier per submission.
 *
 * Inert until a matching allow2ban rule exists: enable the default rule in the
 * extension configuration, or define one in phirewall.php. Reports to an
 * unknown rule name are ignored.
 */
final class FloodProtectionFinisher extends AbstractFinisher
{
    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {}

    protected function executeInternal(): void
    {
        $requestContext = $this->finisherContext->getRequest()->getAttribute(RequestContext::ATTRIBUTE_NAME);
        if (!$requestContext instanceof RequestContext) {
            // The firewall middleware did not run for this request.
            return;
        }

        $configuredRuleIdentifier = $this->options['ruleIdentifier'] ?? null;
        $ruleIdentifier = is_string($configuredRuleIdentifier) && trim($configuredRuleIdentifier) !== ''
            ? trim($configuredRuleIdentifier)
            : FormFloodSettings::DEFAULT_RULE_IDENTIFIER;

        $floodProtectionFinisherTriggered = new FloodProtectionFinisherTriggered($ruleIdentifier);
        $this->eventDispatcher->dispatch($floodProtectionFinisherTriggered);

        $ruleIdentifier = trim($floodProtectionFinisherTriggered->ruleIdentifier);
        if ($ruleIdentifier === '') {
            return;
        }

        // No key: the firewall resolves the client IP through its own,
        // trusted-proxy aware resolver when it processes the signal.
        $requestContext->recordHit($ruleIdentifier);
    }
}
