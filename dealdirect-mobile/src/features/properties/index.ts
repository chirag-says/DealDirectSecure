/**
 * Properties feature. Cross-feature imports come through this file only.
 */

export {
  adaptProperty,
  adaptPropertyDetail,
  flattenGallery,
  normalizeListingType,
} from './adapters';
export {
  fetchPropertyDetail,
  fetchPropertyPage,
  fetchSuggestions,
  SEARCH_PAGE_SIZE,
  type PropertyPage,
} from './api';
export {
  usePropertyDetail,
  usePropertyFeed,
  useRecordPropertyView,
  type PropertyDetailQuery,
  type PropertyFeed,
} from './hooks';
export { DetailHero, heroHeight, type DetailHeroProps } from './components/DetailHero';
export {
  DetailHeader,
  HEADER_BAR_HEIGHT,
  useHeaderProgress,
  type DetailHeaderProps,
} from './components/DetailHeader';
export {
  DetailSectionNav,
  SECTION_NAV_HEIGHT,
  useSectionRegistry,
  type DetailSection,
  type DetailSectionNavProps,
} from './components/DetailSectionNav';
export { ExpandableText, type ExpandableTextProps } from './components/ExpandableText';
export { DetailFacts, type DetailFactsProps } from './components/DetailFacts';
export { DetailOwner, type DetailOwnerProps } from './components/DetailOwner';
export { ZoomableImage, type ZoomableImageProps } from './components/ZoomableImage';
export {
  DetailAttributes,
  type DetailAttributesProps,
} from './components/DetailAttributes';
export {
  resolveFieldSections,
  type FieldRow,
  type FieldSection,
} from './fieldMap';
export { DetailActions, type DetailActionsProps } from './components/DetailActions';
export { ReportSheet, type ReportSheetProps } from './components/ReportSheet';
export { VideoWalkthrough, type VideoWalkthroughProps } from './components/VideoWalkthrough';
export { NearbyPlaces, type NearbyPlacesProps } from './components/NearbyPlaces';
export { EmiCalculator, type EmiCalculatorProps } from './components/EmiCalculator';
export { useInterest, type InterestState } from './interest';
export {
  PropertyCard,
  COVER_ASPECT,
  CARD_RADIUS,
  type PropertyCardProps,
  type CompareControlProps,
  type SaveControlProps,
} from './components/PropertyCard';
export { PropertyListItem } from './components/PropertyListItem';
export { SavedPropertyCard, type SavedPropertyCardProps } from './components/SavedPropertyCard';
export { PropertyCardSkeleton, PropertyListSkeleton } from './components/PropertyCardSkeleton';
export { PropertyList, type PropertyListProps } from './components/PropertyList';
export { PropertyStrip, type PropertyStripProps } from './components/PropertyStrip';
export { PropertyRail, type PropertyRailProps } from './components/PropertyRail';
export {
  PropertyRailCard,
  type PropertyRailCardProps,
} from './components/PropertyRailCard';
export {
  recordView,
  clearRecentlyViewed,
  useRecentlyViewed,
  useRecordView,
  type ViewedProperty,
} from './recentlyViewed';
export type {
  GalleryImage,
  ListingIntent,
  PropertyCoordinates,
  PropertyDetail,
  PropertyOwnerContact,
  PropertySummary,
} from './types';
