<?php
declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend\Controller;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use Flowd\Typo3Firewall\Pattern\PhpArrayPatternBackend;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

#[AsController]
class FirewallController extends ActionController
{
    public function __construct(
        private readonly ModuleTemplateFactory $moduleTemplateFactory,
    ) {
    }

    protected function errorAction(): ResponseInterface
    {
return parent::errorAction();
    }

    public function overviewAction(): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $phpArrayPatternBackend = $this->getBackend();

        $moduleTemplate->assignMultiple([
            'patterns' => $phpArrayPatternBackend->listRaw(),
            'kinds' => array_combine(PatternKind::all(), PatternKind::all()),
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Overview');
    }

    public function createAction(PatternEntryDto $patternEntryDto): ResponseInterface
    {
        $this->getBackend()->append($patternEntryDto->toPatternEntry());
        return $this->redirect('overview');
    }

    public function deleteAction(string $id): ResponseInterface
    {
        $this->getBackend()->removeById($id);
        return $this->redirect('overview');
    }

    public function pruneAction(): ResponseInterface
    {
        $this->getBackend()->pruneExpired();
        return $this->redirect('overview');
    }

    private function getBackend(): PhpArrayPatternBackend
    {
        $base = (Environment::getProjectPath() !== Environment::getPublicPath())
            ? Environment::getConfigPath()
            : Environment::getLegacyConfigPath();
        $path = $base . '/system/phirewall.patterns.php';
        return new PhpArrayPatternBackend($path);
    }
}
