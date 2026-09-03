<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Backend;

use Flowd\Typo3Firewall\EventLog\EventLogViewDataProvider;
use Flowd\Typo3Firewall\EventLog\FirewallEventType;
use TYPO3\CMS\Backend\Module\ModuleData;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Extbase\Mvc\RequestInterface;

/**
 * Reads and persists the firewall module state in the backend user's module
 * data: the last visited view, the event log filters, and the statistics
 * range. Keeps that per-user persistence out of the controller.
 */
final class FirewallModuleState
{
    /** Bounds the search term before it is used and persisted in the user's uc. */
    private const int MAX_SEARCH_LENGTH = 200;

    /** Actions that render a view and can become the remembered default. */
    private const array VIEW_ACTIONS = ['overview', 'bans', 'events', 'statistics'];

    /**
     * Remember the currently requested view as the module's default view.
     */
    public function rememberSelectedView(RequestInterface $request): void
    {
        $moduleData = $request->getAttribute('moduleData');
        $action = (string)($request->getArguments()['action'] ?? '');
        if (!$moduleData instanceof ModuleData || !in_array($action, self::VIEW_ACTIONS, true)) {
            return;
        }

        if ($moduleData->get('defaultAction', '') !== $action) {
            $moduleData->set('defaultAction', $action);
            $this->persist($moduleData);
        }
    }

    /**
     * The view the user worked with last, or the overview as fallback.
     */
    public function defaultView(RequestInterface $request): string
    {
        $moduleData = $request->getAttribute('moduleData');
        $defaultAction = $moduleData instanceof ModuleData ? $moduleData->get('defaultAction', '') : '';

        return is_string($defaultAction) && in_array($defaultAction, self::VIEW_ACTIONS, true) ? $defaultAction : 'overview';
    }

    /**
     * Persist or restore the type, search, excluded-key and range filters.
     * Filter submits and tag toggles carry operation=filter and persist their
     * state; plain navigation without any filter arguments restores it. The
     * key and rule filters are transient drill-downs and are never persisted;
     * a request carrying one shows it unfiltered instead of restoring the
     * stored filters.
     *
     * @param array<mixed> $types
     * @param array<mixed> $excludeKeys
     * @return array{0: list<string>, 1: string, 2: list<string>, 3: string}
     */
    public function resolveEventFilters(RequestInterface $request, array $types, string $search, string $key, string $rule, string $operation, array $excludeKeys = [], string $range = ''): array
    {
        $requestedFilters = $this->sanitizeEventFilters($types, $search, $excludeKeys, $range);
        $moduleData = $request->getAttribute('moduleData');
        if (!$moduleData instanceof ModuleData) {
            return $requestedFilters;
        }

        if ($operation === 'reset-filters') {
            $moduleData->set('eventsFilter', []);
            $this->persist($moduleData);

            return [[], '', [], ''];
        }

        if ($operation === 'filter') {
            [$stringTypes, $sanitizedSearch, $excludeKeyHashes, $sanitizedRange] = $requestedFilters;
            $moduleData->set('eventsFilter', [
                'types' => $stringTypes,
                'search' => $sanitizedSearch,
                'excludeKeys' => $excludeKeyHashes,
                'range' => $sanitizedRange,
            ]);
            $this->persist($moduleData);

            return $requestedFilters;
        }

        if ($key === '' && $rule === '' && $requestedFilters === [[], '', [], '']) {
            return $this->restorePersistedEventFilters($moduleData);
        }

        return $requestedFilters;
    }

    /**
     * @param array<mixed> $types
     * @param array<mixed> $excludeKeys
     * @return array{0: list<string>, 1: string, 2: list<string>, 3: string}
     */
    private function sanitizeEventFilters(array $types, string $search, array $excludeKeys, string $range): array
    {
        return [
            $this->filterKnownEventTypes($types),
            mb_substr($search, 0, self::MAX_SEARCH_LENGTH),
            EventLogViewDataProvider::sanitizeExcludeKeys($excludeKeys),
            isset(EventLogViewDataProvider::RANGES[$range]) ? $range : '',
        ];
    }

    /**
     * Persist or restore the statistics range; an explicit range is stored,
     * plain navigation restores the stored one.
     */
    public function resolveStatisticsRange(RequestInterface $request, string $range): string
    {
        $moduleData = $request->getAttribute('moduleData');
        if (!$moduleData instanceof ModuleData) {
            return $range;
        }

        if ($range === '') {
            $persistedRange = $moduleData->get('statisticsRange', '');

            return is_string($persistedRange) ? $persistedRange : '';
        }

        $moduleData->set('statisticsRange', $range);
        $this->persist($moduleData);

        return $range;
    }

    /**
     * @return array{0: list<string>, 1: string, 2: list<string>, 3: string}
     */
    private function restorePersistedEventFilters(ModuleData $moduleData): array
    {
        $persistedFilter = $moduleData->get('eventsFilter', []);
        if (!is_array($persistedFilter)) {
            return [[], '', [], ''];
        }

        $persistedTypes = is_array($persistedFilter['types'] ?? null) ? $persistedFilter['types'] : [];
        $persistedSearch = $persistedFilter['search'] ?? null;
        $persistedExcludeKeys = is_array($persistedFilter['excludeKeys'] ?? null) ? $persistedFilter['excludeKeys'] : [];
        $persistedRange = $persistedFilter['range'] ?? null;

        return [
            $this->filterKnownEventTypes($persistedTypes),
            is_string($persistedSearch) ? mb_substr($persistedSearch, 0, self::MAX_SEARCH_LENGTH) : '',
            EventLogViewDataProvider::sanitizeExcludeKeys($persistedExcludeKeys),
            is_string($persistedRange) && isset(EventLogViewDataProvider::RANGES[$persistedRange]) ? $persistedRange : '',
        ];
    }

    /**
     * Keep only known event type values, so nothing else reaches the query
     * layer or the persisted module data.
     *
     * @param array<mixed> $types
     * @return list<string>
     */
    private function filterKnownEventTypes(array $types): array
    {
        $knownTypes = [];
        foreach ($types as $type) {
            if (is_string($type) && FirewallEventType::tryFrom($type) instanceof FirewallEventType && !in_array($type, $knownTypes, true)) {
                $knownTypes[] = $type;
            }
        }

        return $knownTypes;
    }

    private function persist(ModuleData $moduleData): void
    {
        $this->getBackendUser()->pushModuleData($moduleData->getModuleIdentifier(), $moduleData->toArray());
    }

    private function getBackendUser(): BackendUserAuthentication
    {
        /** @var BackendUserAuthentication $backendUser */
        $backendUser = $GLOBALS['BE_USER'];

        return $backendUser;
    }
}
