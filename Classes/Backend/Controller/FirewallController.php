<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend\Controller;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\ConfigFactory;
use Flowd\Typo3Firewall\Dto\PatternEntryDto;
use Flowd\Typo3Firewall\Pattern\FileArrayPatternBackend;
use Flowd\Typo3Firewall\Writer\FileArrayWriter;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

#[AsController]
class FirewallController extends ActionController
{
    private ?FileArrayPatternBackend $fileArrayPatternBackend = null;

    public function __construct(
        private readonly ModuleTemplateFactory $moduleTemplateFactory,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function overviewAction(?string $editId = null): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $fileArrayPatternBackend = $this->getBackend();

        $editPattern = null;
        if ($editId !== null) {
            $editPattern = $this->findPatternById($editId);
            if ($editPattern === null) {
                $this->addFlashMessage('Pattern not found.', 'Error', ContextualFeedbackSeverity::ERROR);
            }
        }

        $moduleTemplate->assignMultiple([
            'patterns' => $fileArrayPatternBackend->listRaw(),
            'kinds' => PatternKind::cases(),
            'now' => time(),
            'editPattern' => $editPattern,
            'isEditMode' => $editPattern !== null,
            'integrityIssue' => $fileArrayPatternBackend->checkIntegrity(),
        ]);

        return $moduleTemplate->renderResponse('Backend/Firewall/Overview');
    }

    public function createAction(PatternEntryDto $patternEntryDto): ResponseInterface
    {
        try {
            $this->getBackend()->append($patternEntryDto->toPatternEntry());
            $this->addFlashMessage('Pattern created successfully.');
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($invalidArgumentException->getMessage(), 'Validation Error', ContextualFeedbackSeverity::ERROR);
        }

        return $this->redirect('overview');
    }

    public function updateAction(string $id, PatternEntryDto $patternEntryDto): ResponseInterface
    {
        try {
            $entry = $patternEntryDto->toPatternEntry();
            $this->getBackend()->append(new PatternEntry(
                kind: $entry->kind,
                value: $entry->value,
                target: $entry->target,
                expiresAt: $entry->expiresAt,
                metadata: ['id' => $id],
            ));

            $this->addFlashMessage('Pattern updated successfully.');
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->addFlashMessage($invalidArgumentException->getMessage(), 'Validation Error', ContextualFeedbackSeverity::ERROR);
            return $this->redirect('overview', null, null, ['editId' => $id]);
        }

        return $this->redirect('overview');
    }

    public function deleteAction(string $id): ResponseInterface
    {
        $this->getBackend()->removeById($id);
        $this->addFlashMessage('Pattern deleted successfully.');
        return $this->redirect('overview');
    }

    public function pruneAction(): ResponseInterface
    {
        $this->getBackend()->pruneExpired();
        $this->addFlashMessage('Expired patterns pruned.');
        return $this->redirect('overview');
    }

    private function getBackend(): FileArrayPatternBackend
    {
        if ($this->fileArrayPatternBackend instanceof FileArrayPatternBackend) {
            return $this->fileArrayPatternBackend;
        }

        $path = ConfigFactory::getPatternsFilePath();
        return $this->fileArrayPatternBackend = new FileArrayPatternBackend(
            $path,
            new FileArrayWriter($path, $this->logger),
            $this->logger
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findPatternById(string $id): ?array
    {
        $patterns = $this->getBackend()->listRaw();
        foreach ($patterns as $pattern) {
            if (($pattern['id'] ?? null) === $id) {
                return $pattern;
            }
        }

        return null;
    }
}
