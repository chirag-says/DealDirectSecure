/**
 * Home feature: the personal command centre.
 *
 * Home owns no browsing and no inventory. Every affordance here routes to
 * Search, so there is a single infinite scroll, a single filter sheet and a
 * single sort in the app. Nothing on this screen paginates.
 *
 * The test for anything added here is whether it is ABOUT THIS USER. Content
 * that describes the product belongs on the website; content that lists
 * properties belongs on Search.
 *
 * `collections.ts`, `useCityCounts` and `usePopularListings` remain exported
 * and are currently unused by any screen — they were the old Home's editorial
 * rails, each costing one request against a 20-per-minute limiter. They are
 * kept because they are correct and cheap to remount if Search ever wants a
 * browse surface; nothing on Home should call them.
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
export { HomeGreeting, type HomeGreetingProps } from './components/HomeGreeting';
export { HomeHero, type HomeHeroProps } from './components/HomeHero';
export {
  HomeHeader,
  SEARCH_PIN_WINDOW,
  type HomeHeaderProps,
} from './components/HomeHeader';
export { CityPickerSheet, type CityPickerSheetProps } from './components/CityPickerSheet';
export { setSelectedCity, useSelectedCity } from './city';
export {
  ActivitySnapshot,
  type ActivitySnapshotProps,
  type SnapshotTile,
} from './components/ActivitySnapshot';
export { UpdatesPreview, type UpdatesPreviewProps } from './components/UpdatesPreview';
export { ListingCard, type ListingCardProps, type ListingCardState } from './components/ListingCard';
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
export { detectCity, type DetectCityResult } from './detectCity';
