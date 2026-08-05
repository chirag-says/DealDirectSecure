/**
 * Saved searches. Cross-feature imports come through this file only.
 */

export { adaptSavedSearch, decodeSearchName } from './adapters';
export {
  useSavedSearches,
  useCreateSavedSearch,
  useUpdateSavedSearchAlerts,
  useDeleteSavedSearch,
  type SavedSearchListState,
} from './hooks';
export { SavedSearchRow, type SavedSearchRowProps } from './components/SavedSearchRow';
export { SaveSearchSheet, type SaveSearchSheetProps } from './components/SaveSearchSheet';
export {
  PRICE_BAND_LABELS,
  PRICE_BAND_ORDER,
  type SavedSearchPriceBand,
  type SavedSearchSummary,
} from './types';
