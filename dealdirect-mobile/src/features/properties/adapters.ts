/**
 * Backend `Property` → `PropertySummary`.
 *
 * Every irregularity in the property schema is absorbed here. If a component
 * anywhere needs a `??` chain over backend fields, that chain belongs in this
 * file instead.
 */

import type {
  Property,
  PropertyCategorizedImages,
  PropertyListingType,
} from '@/types/backend/property';
import type { Category, PropertyType, SubCategory } from '@/types/backend/taxonomy';
import type {
  GalleryImage,
  ListingIntent,
  PropertyCoordinates,
  PropertyDetail,
  PropertyOwnerContact,
  PropertySummary,
} from './types';

/**
 * `listingType` enumerates `Rent | Sell | Sale | rent | sell | sale`: three
 * meanings across two casings, with two spellings of "sale". Comparing the raw
 * value works for whichever casing the author happened to test with and fails
 * silently for the rest.
 */
const INTENT_BY_LISTING_TYPE: Record<PropertyListingType, ListingIntent> = {
  Rent: 'rent',
  rent: 'rent',
  Sell: 'sale',
  sell: 'sale',
  Sale: 'sale',
  sale: 'sale',
};

export function normalizeListingType(value: string | undefined): ListingIntent | null {
  if (!value) return null;
  return INTENT_BY_LISTING_TYPE[value as PropertyListingType] ?? null;
}

/**
 * Reads a `name` off a taxonomy field that may be an id or a populated
 * document. `/properties/search` populates all three with `name` only, but
 * other endpoints do not, and the denormalised `categoryName` /
 * `propertyTypeName` columns are more reliable than either.
 */
function taxonomyName(
  ref: Category | SubCategory | PropertyType | string | undefined
): string | undefined {
  if (!ref || typeof ref === 'string') return undefined;
  return ref.name;
}

/** Ordered buckets in `categorizedImages`, flattened for a cover-image fallback. */
function firstCategorizedImage(images: PropertyCategorizedImages | undefined): string | undefined {
  if (!images) return undefined;

  for (const group of [images.residential, images.commercial]) {
    if (!group) continue;
    for (const bucket of Object.values(group)) {
      if (Array.isArray(bucket) && bucket.length > 0) return bucket[0];
    }
  }

  return undefined;
}

function countImages(property: Property): number {
  const flat = property.images?.length ?? 0;

  let categorized = 0;
  for (const group of [
    property.categorizedImages?.residential,
    property.categorizedImages?.commercial,
  ]) {
    if (!group) continue;
    for (const bucket of Object.values(group)) {
      if (Array.isArray(bucket)) categorized += bucket.length;
    }
  }

  return flat + categorized;
}

/**
 * The five area fields, in the order a listing is most likely to carry a
 * meaningful one. Carpet area is the most honest figure but the least often
 * filled in, so it is not first.
 */
function resolveArea(property: Property): number | undefined {
  const { area } = property;
  if (!area) return undefined;

  const candidates = [
    area.totalSqft,
    area.builtUpSqft,
    area.superBuiltUpSqft,
    area.carpetSqft,
    area.plotSqft,
  ];

  return candidates.find((value): value is number => typeof value === 'number' && value > 0);
}

/**
 * Coordinates, only when BOTH are usable numbers.
 *
 * `withPublicImages` promotes `address.latitude`/`longitude` to top-level
 * `lat`/`lng` when both are present, but the underlying fields are optional and
 * unindexed. Zero is rejected as well as absent: a (0, 0) pin is in the Gulf of
 * Guinea and reads as a real location to a map, which is worse than no pin.
 */
function resolveCoordinates(property: Property): PropertyCoordinates | null {
  const lat = property.lat ?? property.address?.latitude;
  const lng = property.lng ?? property.address?.longitude;

  if (typeof lat !== 'number' || typeof lng !== 'number') return null;
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (lat === 0 && lng === 0) return null;

  return { lat, lng };
}

function composeLocation(locality: string | undefined, city: string | undefined): string {
  return [locality, city].filter(Boolean).join(', ');
}

/**
 * Is this title machine-composed from fields the card already renders?
 *
 * `generateTitle()` in the website's add-property form builds
 * `<BHK> <propertyTypeName> for <Rent|Sale> in <locality>`. Every one of those
 * parts appears elsewhere on the card, so showing the title too prints the
 * listing's facts twice and buries the price.
 *
 * Detection is deliberately conservative: it requires BOTH the listing-intent
 * phrase and the property type to be present. A hand-written title that happens
 * to contain "for Rent" still survives unless it also names the type, and the
 * cost of a false negative is one extra line, not a wrong one.
 */
function isGeneratedTitle(title: string, propertyTypeName: string | undefined): boolean {
  if (!propertyTypeName) return false;
  if (!/\bfor (rent|sale)\b/i.test(title)) return false;
  return title.toLowerCase().includes(propertyTypeName.toLowerCase());
}

export function adaptProperty(property: Property): PropertySummary {
  const city = property.address?.city ?? property.city ?? undefined;
  const locality = property.locality ?? property.address?.area ?? undefined;
  const propertyTypeName = property.propertyTypeName ?? taxonomyName(property.propertyType);

  return {
    id: property._id,
    title: property.title,
    headline: isGeneratedTitle(property.title, propertyTypeName) ? undefined : property.title,

    // Rupees, as stored. `priceUnit` is NOT applied: it holds the schema
    // default "Lac" on most rows regardless of the value beside it, so using it
    // as a multiplier inflates a rent by five orders of magnitude. Reasoning
    // and the supporting data are in src/ui/PriceLabel.tsx.
    priceRupees: Number(property.price) || 0,
    priceUnit: property.priceUnit,
    negotiable: property.negotiable ?? false,

    intent: normalizeListingType(property.listingType),

    coverImage: property.images?.[0] ?? firstCategorizedImage(property.categorizedImages),
    imageCount: countImages(property),

    city,
    locality,
    locationLabel: composeLocation(locality, city),

    categoryName: property.categoryName ?? taxonomyName(property.category),
    subcategoryName: taxonomyName(property.subcategory),
    propertyTypeName,

    bhk: property.bhk,
    bedrooms: property.bedrooms,
    bathrooms: property.bathrooms,
    areaSqft: resolveArea(property),

    furnishing: property.furnishing,
    constructionStatus: property.constructionStatus,

    coordinates: resolveCoordinates(property),

    // The only behavioural signal this backend records. Incremented by
    // `GET /properties/:id`, so it counts detail-screen opens across every
    // client. Defaulted to 0 rather than left undefined so that sorting by it
    // never has to decide what an absent value means.
    views: property.views ?? 0,

    createdAt: property.createdAt,
  };
}

// --- Detail ---------------------------------------------------------------

/**
 * Bucket key → display label, for both category sets.
 *
 * A table rather than a `camelCase → Title Case` function because three of
 * these do not survive mechanical conversion: `kitchenCommercial` would read
 * "Kitchen commercial", `floorPlan` is a document rather than a room, and
 * `other` needs a label that does not look like a missing value.
 *
 * Iteration order is the display order. Exteriors and facades come first
 * because that is what a listing is recognised by; floor plans and "other" go
 * last because they are reference material, not rooms.
 */
const GALLERY_LABELS: Record<string, string> = {
  // Residential
  exterior: 'Exterior',
  livingRoom: 'Living room',
  hall: 'Hall',
  diningArea: 'Dining area',
  kitchen: 'Kitchen',
  bedroom: 'Bedroom',
  bathroom: 'Bathroom',
  balcony: 'Balcony',
  studyRoom: 'Study room',
  poojaRoom: 'Pooja room',
  garden: 'Garden',
  // Commercial
  facade: 'Facade',
  reception: 'Reception',
  workArea: 'Work area',
  seatingArea: 'Seating area',
  cabin: 'Cabin',
  conferenceRoom: 'Conference room',
  shopFloor: 'Shop floor',
  displayArea: 'Display area',
  warehouse: 'Warehouse',
  loadingArea: 'Loading area',
  storageArea: 'Storage',
  kitchenCommercial: 'Kitchen',
  pantry: 'Pantry',
  washroom: 'Washroom',
  // Shared, deliberately last
  parking: 'Parking',
  floorPlan: 'Floor plan',
  other: 'More photos',
};

/** Display order for categorised buckets. Keys absent here are appended after. */
const GALLERY_ORDER = Object.keys(GALLERY_LABELS);

/**
 * Every image on the listing, flattened and labelled, duplicates removed.
 *
 * The flat `images[]` array comes first: it is what the owner uploaded as the
 * listing's own photos and its first entry is the cover the whole app already
 * shows, so the gallery must open on the same picture the card displayed.
 *
 * The same URL can appear in both `images[]` and a categorised bucket — the
 * website's add-property form writes some uploads to both — so a `Set` keeps
 * the first occurrence and drops the rest. Without it the carousel shows the
 * cover photo twice, several screens apart, which reads as a loading bug.
 */
export function flattenGallery(property: Property): GalleryImage[] {
  const seen = new Set<string>();
  const gallery: GalleryImage[] = [];

  const push = (uri: string, bucket?: string) => {
    if (typeof uri !== 'string' || !uri || seen.has(uri)) return;
    seen.add(uri);
    gallery.push({ uri, bucket, label: bucket ? GALLERY_LABELS[bucket] : undefined });
  };

  for (const uri of property.images ?? []) push(uri);

  for (const group of [
    property.categorizedImages?.residential,
    property.categorizedImages?.commercial,
  ]) {
    if (!group) continue;

    const keys = Object.keys(group).sort((a, b) => {
      const ia = GALLERY_ORDER.indexOf(a);
      const ib = GALLERY_ORDER.indexOf(b);
      // Unknown buckets sort last, in whatever order the backend sent them,
      // rather than jumping to the front on `indexOf` returning -1.
      return (ia === -1 ? Number.MAX_SAFE_INTEGER : ia) - (ib === -1 ? Number.MAX_SAFE_INTEGER : ib);
    });

    for (const key of keys) {
      const bucket = (group as Record<string, string[] | undefined>)[key];
      if (!Array.isArray(bucket)) continue;
      for (const uri of bucket) push(uri, key);
    }
  }

  return gallery;
}

/**
 * The owner, when the populate produced a document rather than a bare id.
 *
 * `GET /properties/:id` populates `name email phone profileImage`; every other
 * property endpoint leaves `owner` as an ObjectId string. Returning null for
 * the unpopulated case is what stops a contact button rendering with nothing
 * behind it.
 */
function resolveOwner(property: Property): PropertyOwnerContact | null {
  const { owner } = property;
  if (!owner || typeof owner === 'string') return null;

  return {
    id: owner._id,
    name: owner.name,
    phone: owner.phone,
    email: owner.email,
    profileImage: owner.profileImage,
  };
}

/**
 * Backend `Property` → `PropertyDetail`.
 *
 * Built on `adaptProperty` so the price, intent, location and area fallbacks
 * are resolved by exactly the code the card used. A detail screen that
 * disagrees with the card the user tapped is a bug report every time.
 *
 * One field is knowingly stale: `views` is read BEFORE the controller's
 * `$inc`, so it is the count excluding this open. Nothing renders it on this
 * screen, and `usePopularListings` ranks from the search feed, so the
 * off-by-one never reaches a user.
 */
export function adaptPropertyDetail(property: Property): PropertyDetail {
  return {
    ...adaptProperty(property),

    description: property.description?.trim() || undefined,
    videoUrl: property.videoUrl,

    gallery: flattenGallery(property),
    // Blank strings are filtered: the website's amenity editor writes an empty
    // entry when a row is added and left unfilled, and an empty chip is worse
    // than a missing one.
    amenities: (property.amenities ?? []).map((a) => a?.trim()).filter((a): a is string => !!a),

    owner: resolveOwner(property),

    addressLine: property.address?.line,
    state: property.address?.state,
    pincode: property.address?.pincode,
    landmark: property.address?.landmark,
    nearby: (property.address?.nearby ?? []).map((n) => n?.trim()).filter((n): n is string => !!n),

    availableFrom: property.availableFrom,
    status: property.status,

    raw: property,
  };
}
