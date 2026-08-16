/**
 * Search feature. Cross-feature imports come through this file only.
 */

export {
  BHK_OPTIONS,
  CATEGORY_OPTIONS,
  CITY_OPTIONS,
  CONSTRUCTION_STATUS_OPTIONS,
  DEFAULT_FILTERS,
  FURNISHING_OPTIONS,
  LISTING_TYPE_OPTIONS,
  PRICE_BANDS,
  SORT_OPTIONS,
  bandForPrice,
  bhkCount,
  countActiveFilters,
  findPriceBand,
  hasAnyCriteria,
  hasClientOnlyFilters,
  matchesClientFilters,
  toSearchParams,
  type PriceBand,
  type SearchFilters,
} from './filters';

export { COMPARE_ROWS, MAX_COMPARE, MIN_COMPARE, canAddToCompare, type CompareRow } from './compare';

export {
  RELATED_THRESHOLD,
  useCompareSelection,
  useRecentSearches,
  usePropertySearchFeed,
  useRelatedProperties,
  useSimilarProperties,
  useSuggestions,
  type CompareSelection,
  type RelatedPropertiesResult,
  type Suggestions,
} from './hooks';
export {
  addRecentSearch,
  clearRecentSearches,
  readRecentSearches,
  removeRecentSearch,
} from './recent';

export { SearchBar, SearchTrigger, type SearchBarProps } from './components/SearchBar';
export {
  RecentSearches,
  SuggestionList,
  type RecentSearchesProps,
  type SuggestionListProps,
} from './components/SuggestionList';
export { FilterSheet, type FilterSheetProps } from './components/FilterSheet';
export { FacetSheet, type FacetSheetProps, type FacetOption } from './components/FacetSheet';
export { FiltersButton, QuickFilterBar, type QuickFilterBarProps } from './components/QuickFilterBar';
export { ResultsToolbar, type ResultsToolbarProps } from './components/ResultsToolbar';
export {
  RelatedProperties,
  type RelatedPropertiesProps,
} from './components/RelatedProperties';
export { CompareBar, type CompareBarProps } from './components/CompareBar';
export { CompareSheet, type CompareSheetProps } from './components/CompareSheet';
