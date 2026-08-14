/**
 * Home feature: discovery and navigation only.
 *
 * Home owns no browsing. Every affordance here routes to the one canonical
 * results screen with a filter prefilled, so there is a single infinite scroll,
 * a single filter sheet and a single sort in the app. Nothing on this screen
 * paginates.
 *
 * The editorial half of the screen is driven entirely by `collections.ts`. To
 * add a row, add a row to that table.
 */

export { BROWSE_SHORTCUTS, POPULAR_SEARCHES, type BrowseShortcut } from './catalog';
export {
  COLLECTIONS,
  HOME_COLLECTION_IDS,
  LOCALITIES,
  findCollection,
  type Collection,
  type Locality,
} from './collections';
export { CITIES, citySearchTerm, matchCity, normalizeCityName, type City } from './cities';
export { homeImagery, localityImagery, type HomeImagery } from './imagery';
export { useCollection, RAIL_LENGTH, type CollectionResult } from './useCollection';
export { useCityCounts, type CityCount, type CityCountsResult } from './useCityCounts';
export { usePopularListings, type PopularListingsResult } from './usePopularListings';

export { Section, type SectionProps } from './components/Section';
export { RecentlyViewed, type RecentlyViewedProps } from './components/RecentlyViewed';
export { IntentCards, type IntentCardsProps } from './components/IntentCards';
export { BrowseRow, PopularSearches, type BrowseRowProps } from './components/BrowseRow';
export { Hero, type HeroProps } from './components/Hero';
export { HeroSearchField, type HeroSearchFieldProps } from './components/HeroSearchField';
export { CityGrid, type CityGridProps } from './components/CityGrid';
export { CollectionRail, type CollectionRailProps } from './components/CollectionRail';
export { CtaBanner, type CtaBannerProps } from './components/CtaBanner';
export { AboutDealDirect } from './components/AboutDealDirect';
export { TrustStrip } from './components/TrustStrip';
