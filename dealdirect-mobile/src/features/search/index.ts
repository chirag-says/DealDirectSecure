/**
 * Search feature. Cross-feature imports come through this file only.
 */

export {
  CATEGORY_OPTIONS,
  CITY_OPTIONS,
  CONSTRUCTION_STATUS_OPTIONS,
  DEFAULT_FILTERS,
  FURNISHING_OPTIONS,
  LISTING_TYPE_OPTIONS,
  PRICE_BANDS,
  SORT_OPTIONS,
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
export {
  RelatedProperties,
  type RelatedPropertiesProps,
} from './components/RelatedProperties';
export { CompareBar, type CompareBarProps } from './components/CompareBar';
export { CompareSheet, type CompareSheetProps } from './components/CompareSheet';
