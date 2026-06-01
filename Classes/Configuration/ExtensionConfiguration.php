<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Configuration;

use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

#[Autoconfigure(public: true)]
final readonly class ExtensionConfiguration
{
    public FormFloodingProtection $formFloodingProtection;

    public function __construct(
        #[Autowire(expression: 'service("extension-configuration").get("firewall")')]
        array $setting
    ) {
        $this->formFloodingProtection = FormFloodingProtection::tryFrom($setting['form']['flooding'] ?? []);
    }
}
