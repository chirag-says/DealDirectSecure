/**
 * Search feature. Cross-feature imports come through this file only.
 */

export {
  DEFAULT_FILTERS,
  LISTING_TYPE_OPTIONS,
  PRICE_BANDS,
  SORT_OPTIONS,
  countActiveFilters,
  findPriceBand,
  hasAnyCriteria,
  toSearchParams,
  type PriceBand,
  type SearchFilters,
} from './filters';

export { useRecentSearches, useSuggestions, type Suggestions } from './hooks';
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
