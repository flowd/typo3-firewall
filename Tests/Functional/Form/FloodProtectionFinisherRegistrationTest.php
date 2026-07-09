<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Functional\Form;

use Flowd\Typo3Firewall\Form\Finisher\FloodProtectionFinisher;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The form framework instantiates finishers via GeneralUtility::makeInstance(),
 * which resolves constructor dependencies only for public container services.
 * Guards the conditional registration in Configuration/Services.php.
 */
#[CoversNothing]
final class FloodProtectionFinisherRegistrationTest extends FunctionalTestCase
{
    protected array $coreExtensionsToLoad = [
        'form',
    ];

    protected array $testExtensionsToLoad = [
        'flowd/typo3-firewall',
    ];

    #[Test]
    public function finisherIsAvailableThroughMakeInstanceWithPrototypeScope(): void
    {
        $floodProtectionFinisher = GeneralUtility::makeInstance(FloodProtectionFinisher::class);
        $secondFloodProtectionFinisher = GeneralUtility::makeInstance(FloodProtectionFinisher::class);

        self::assertNotSame($floodProtectionFinisher, $secondFloodProtectionFinisher);
    }
}
