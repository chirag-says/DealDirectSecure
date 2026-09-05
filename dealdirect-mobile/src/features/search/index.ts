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

export {
  COMPARE_ROWS,
  MAX_COMPARE,
  MIN_COMPARE,
  canAddToCompare,
  type ComparableProperty,
  type CompareRow,
} from './compare';

export {
  RELATED_THRESHOLD,
  useCompareSelection,
  useRecentSearches,
  usePropertySearchFeed,
  useRelatedProperties,
  useSearchPreview,
  useSimilarProperties,
  useSuggestions,
  type CompareSelection,
  type RelatedPropertiesResult,
  type SearchPreview,
  type Suggestions,
} from './hooks';
export {
  addRecentSearch,
  clearRecentSearches,
  readRecentSearches,
  removeRecentSearch,
} from './recent';
export {
  clearResumableSearch,
  recordResumableSearch,
  useResumableSearch,
  type ResumableSearch,
} from './resume';

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
export { SearchScreen } from './components/SearchScreen';
export { ResumeSearchCard, type ResumeSearchCardProps } from './components/ResumeSearchCard';
