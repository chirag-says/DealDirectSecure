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
export { CityGrid, type CityGridProps } from './components/CityGrid';
export { CollectionRail, type CollectionRailProps } from './components/CollectionRail';

/*
 * WHAT IS NO LONGER HERE, AND WHY.
 *
 * `AboutDealDirect` ("Why DealDirect") and `TrustStrip` ("verified properties /
 * direct owners / no hidden fees") were removed on 2026-08-22.
 *
 * `Hero`, `HeroSearchField` and `CtaBanner` followed on 2026-08-24, when the
 * Home tab itself did. The hero carried the website's headline — "Buy, Rent &
 * Sell Properties Directly from Owners. No middleman. No commission fees." —
 * and the banner closed the screen with "Ready to find your home?". Both were
 * addressed to a stranger who had not decided yet, which is not who opens an
 * installed app. The search field they wrapped is now the tab's own, and the
 * bell they carried is now the Updates tab.
 *
 * All five are in git history if the pitch is ever wanted back.
 *
 * What survives here is what a search tool can use: the static browse tables,
 * the city and collection data, and the rails that read from disk.
 */
