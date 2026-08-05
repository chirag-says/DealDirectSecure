/**
 * Property contract. Source: backend/models/Property.js and
 * backend/controllers/propertyController.js.
 *
 * The schema is wide (~80 fields) and splits into a residential and a
 * commercial field set that never both apply. Nearly everything is optional
 * because only `title` is `required` in the schema, so any type that marks
 * fields as present will crash on real data.
 */

import type {
  IsoDate,
  MixedValue,
  ObjectId,
  Timestamps,
} from './common';
import type { Category, PropertyType, SubCategory } from './taxonomy';
import type { User } from './user';

/**
 * `listingType` accepts six values in the schema enum: three meanings across
 * two casings (`Rent|Sell|Sale|rent|sell|sale`). Normalise in the adapter, do
 * not compare raw.
 */
export type PropertyListingType =
  | 'Rent'
  | 'Sell'
  | 'Sale'
  | 'rent'
  | 'sell'
  | 'sale';

export type PropertyStatus =
  | 'active'
  | 'pending'
  | 'sold'
  | 'rented'
  | 'inactive'
  | 'pending_verification';

export interface PropertyArea {
  totalSqft?: number;
  carpetSqft?: number;
  builtUpSqft?: number;
  superBuiltUpSqft?: number;
  plotSqft?: number;
  pricePerSqft?: number;
}

export interface PropertyAddress {
  line?: string;
  area?: string;
  city?: string;
  state?: string;
  pincode?: string;
  landmark?: string;
  nearby?: string[];
  latitude?: number;
  longitude?: number;
}

/**
 * Categorised image buckets. Only one of the two sub-objects is meaningful for
 * a given property, selected by `categoryName`. Flatten this once in the
 * adapter into an ordered, labelled gallery so no component walks the shape.
 */
export interface PropertyCategorizedImages {
  residential?: {
    exterior?: string[];
    livingRoom?: string[];
    bedroom?: string[];
    bathroom?: string[];
    kitchen?: string[];
    balcony?: string[];
    hall?: string[];
    diningArea?: string[];
    studyRoom?: string[];
    poojaRoom?: string[];
    garden?: string[];
    parking?: string[];
    floorPlan?: string[];
    other?: string[];
  };
  commercial?: {
    facade?: string[];
    reception?: string[];
    workArea?: string[];
    cabin?: string[];
    conferenceRoom?: string[];
    pantry?: string[];
    washroom?: string[];
    warehouse?: string[];
    loadingArea?: string[];
    shopFloor?: string[];
    displayArea?: string[];
    seatingArea?: string[];
    kitchenCommercial?: string[];
    storageArea?: string[];
    parking?: string[];
    floorPlan?: string[];
    other?: string[];
  };
}

export interface Property extends Timestamps {
  _id: ObjectId;

  /** Populated with `name email phone profileImage` by `GET /properties/:id`. */
  owner?: ObjectId | Pick<User, '_id' | 'name' | 'email' | 'phone' | 'profileImage'>;
  /** Non-null only for builder-posted listings, which are excluded from the
   *  public property feeds and live under /projects instead. */
  builder?: ObjectId | null;

  category?: ObjectId | Category;
  subcategory?: ObjectId | SubCategory;
  propertyType?: ObjectId | PropertyType;
  /** Denormalised names. More reliable than the refs, which are populated
   *  inconsistently across endpoints. */
  categoryName?: string;
  propertyTypeName?: string;

  title: string;
  description?: string;
  videoUrl?: string;

  price?: number;
  priceUnit?: string;
  negotiable?: boolean;
  gstApplicable?: string;
  bookingAmount?: number;

  area?: PropertyArea;
  amenities?: string[];
  parking?: {
    covered?: MixedValue;
    open?: MixedValue;
  };

  address?: PropertyAddress;
  /** Convenience duplicates of address fields. */
  city?: string;
  locality?: string;

  /** Absolute Cloudinary URLs after `withPublicImages`. */
  images?: string[];
  categorizedImages?: PropertyCategorizedImages;

  /**
   * Promoted to the top level by `withPublicImages`, but ONLY when both
   * `address.latitude` and `address.longitude` are present. Frequently absent.
   */
  lat?: number;
  lng?: number;

  isApproved?: boolean;
  rejectionReason?: string;
  status?: PropertyStatus;
  views?: number;
  likes?: number;
  inquiries?: number;

  interestedUsers?: Array<{
    user: ObjectId | Pick<User, '_id' | 'name' | 'email' | 'phone' | 'profileImage'>;
    interestedAt: IsoDate;
  }>;

  listingType?: PropertyListingType;
  availableFrom?: IsoDate;
  deposit?: MixedValue;

  // Residential
  bhk?: string;
  bedrooms?: number;
  bathrooms?: number;
  balconies?: number;
  furnishing?: string;
  floorNo?: string;
  totalFloors?: string;
  facing?: string;
  constructionStatus?: string;
  propertyAge?: string;
  ageOfProperty?: string;
  allowedFor?: string;
  petFriendly?: string;
  extras?: {
    servantRoom?: boolean;
    poojaRoom?: boolean;
    studyRoom?: boolean;
    storeRoom?: boolean;
  };

  // Commercial
  commercialSubType?: string;
  washrooms?: number;
  loadingArea?: string;
  dockAvailable?: boolean;
  shutters?: string;
  floorHeight?: string;
  powerLoad?: string;
  maintenance?: MixedValue;
  maintenanceIncluded?: boolean;
  securityDeposit?: number;
  workstations?: string;
  conferenceRooms?: string;
  cabins?: string;
  pantry?: string;
  frontage?: string;
  storage?: string;
  displayWindows?: string;
  displayArea?: string;
  seatingCapacity?: string;
  kitchenArea?: string;
  barArea?: string;
  outdoorSeating?: string;
  meetingRooms?: string;
  privateCabins?: string;
  phoneBooths?: string;
  loungeArea?: string;
  loadingDocks?: string;
  ceilingHeight?: string;
  floorLoadCapacity?: string;
  powerConnection?: string;
  overheadCrane?: string;
  centralAC?: string;
  powerBackup?: string;

  legal?: {
    reraId?: string;
    occupancyCertificate?: boolean;
    tradeLicense?: boolean;
    fireNoc?: boolean;
  };
}

// --- Query parameters -----------------------------------------------------

/**
 * `GET /properties/search`.
 *
 * The free-text parameter is `search`. It is NOT `q`. The website's
 * `propertyApi.search` helper sends `q`, which this controller never reads, so
 * that helper silently returns unfiltered results. Documented in
 * docs/API_CONTRACT.md; the backend is not changed.
 */
export interface PropertySearchParams {
  search?: string;
  category?: ObjectId;
  subcategory?: ObjectId;
  propertyType?: ObjectId;
  buildingType?: string;
  size?: string;
  /** The literal string `"All"` is treated by the backend as no filter. */
  city?: string;
  priceFrom?: number;
  priceTo?: number;
  /**
   * Rent versus sale. Added to the backend 2026-08-03 by explicit approval;
   * additive and backward-compatible.
   *
   * Send the INTENT (`rent` / `sale`), not a schema value. The controller
   * expands it to an `$in` over all six enum spellings, because matching
   * `listingType` by equality would silently return only the listings that
   * happen to use the same casing as the caller. An unrecognised value is
   * ignored server-side rather than returning an empty list.
   */
  listingType?: 'rent' | 'sale';
  page?: number;
  /** Backend default is 12. */
  limit?: number;
  sort?: PropertySortOrder;
}

export type PropertySortOrder = 'newest' | 'priceAsc' | 'priceDesc';

/** `GET /properties/suggestions`. This endpoint really does use `q`. */
export interface PropertySuggestionParams {
  /** Fewer than 2 characters returns an empty array without querying. */
  q: string;
}

/**
 * One autocomplete row.
 *
 * CORRECTED 2026-08-03. M0 typed `suggestions` as `string[]`. The controller
 * (`getSuggestions`, propertyController.js:1911) builds OBJECTS from a three-way
 * `$facet` over titles, localities and cities. Read from the source, not from
 * the earlier assumption.
 *
 * `subtitle` is always a string, possibly empty. `image` is present only on
 * `project` rows and is explicitly `null` when the listing has no images.
 */
export interface PropertySuggestion {
  /** `project` is a property TITLE match, not a builder project. */
  type: 'project' | 'locality' | 'city';
  value: string;
  subtitle: string;
  image?: string | null;
}

/** At most 8 rows: 5 titles, 5 localities, 3 cities, deduped then sliced. */
export interface PropertySuggestionsResponse {
  suggestions: PropertySuggestion[];
}

/** `GET /properties/list`. Returns a BARE ARRAY, no envelope. */
export type PropertyListResponse = Property[];

/** `GET /properties/:id`. Returns a BARE OBJECT, no envelope. */
export type PropertyDetailResponse = Property;

/** `GET /properties/interested/:id/check`. */
export interface InterestCheckResponse {
  success: true;
  isInterested: boolean;
}
