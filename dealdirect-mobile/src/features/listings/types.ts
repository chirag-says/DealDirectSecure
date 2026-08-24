/**
 * The owner add/edit listing form's internal shape.
 *
 * This is NOT the wire format. `add` and `edit` submit through genuinely
 * different backend code paths with different field-name and image-handling
 * rules (see `formData.ts`); this shape is what the multi-step form and its
 * zod schema work with, converted at submit time.
 */

/**
 * A category name as the SERVER spells it.
 *
 * A `'Residential' | 'Commercial'` union until 2026-08-24, which was wrong in
 * both directions: it excluded `Land & Plots`, a real category no owner could
 * reach from this app, and it implied a closed set the client is not entitled
 * to decide. The vocabulary is the server's — see `taxonomy.ts` — so this is
 * the server's string, and the two places that genuinely branch on it treat
 * `Commercial` as the special case and everything else as residential-shaped.
 *
 * The hardcoded `RESIDENTIAL_TYPES`/`COMMERCIAL_TYPES` arrays that sat here
 * were deleted with it. They had drifted from the names the backend accepts and
 * were failing six of twelve submissions at the last step; `useListingTaxonomy`
 * fetches the real list instead.
 */
export type ListingCategory = string;

export const AMENITIES = [
  'Lift',
  'Power Backup',
  'Security',
  'Gym',
  'Swimming Pool',
  'Clubhouse',
  'Children Play Area',
  'Park',
  'Intercom',
  'Fire Safety',
  'Rain Water Harvesting',
  'Vaastu Compliant',
] as const;

export interface ListingFormValues {
  categoryName: ListingCategory;
  propertyTypeName: string;
  listingType: 'Rent' | 'Sale';
  title: string;
  description: string;

  addressLine: string;
  city: string;
  locality: string;
  state: string;
  pincode: string;
  landmark: string;

  price: string;
  negotiable: boolean;
  deposit: string;
  maintenance: string;
  securityDeposit: string;

  totalSqft: string;
  carpetSqft: string;
  builtUpSqft: string;
  /**
   * Added 2026-08-13 (defect F13): the website sends these three and mobile
   * could not, so a mobile-created listing showed a blank ₹/sqft line and no
   * super-built-up or plot area on the website. All three are real nested
   * `area.*` schema paths AND on the add whitelist — verified, unlike the flat
   * `builtUpArea`/`carpetArea` whitelist entries the module doc warns about.
   */
  superBuiltUpSqft: string;
  plotSqft: string;

  /**
   * The pinned coordinate, as strings at six decimals — the precision the
   * website stores and the form displays.
   *
   * Strings rather than numbers because they are also editable text fields, and
   * a half-typed "19." is not a number. Parsed at submit.
   */
  latitude: string;
  longitude: string;

  /** `Yes`/`No` on the website's select; sent as the string it shows. */
  gstApplicable: boolean;
  /** Sell only. */
  bookingAmount: string;
  /**
   * Rent only, and default TRUE like the website — most Indian rentals quote an
   * inclusive figure, and defaulting the other way invites a wrong number in
   * the maintenance field.
   */
  maintenanceIncluded: boolean;

  /** Commercial only: Bare Shell / Warm Shell / Fully Furnished. */
  commercialSubType: string;

  /** Optional walkthrough link. Sent verbatim as `videoUrl`. */
  videoUrl: string;

  // Residential
  /** The chip label — `2 BHK`, `Studio`. Sent as `features.bhk`. */
  bhkType: string;
  bhk: string;
  bedrooms: string;
  bathrooms: string;
  balconies: string;
  furnishing: string;
  /** New / 1-5 Years / 5-10 Years / 10+ Years. */
  propertyAge: string;
  floorNo: string;
  totalFloors: string;
  facing: string;
  constructionStatus: string;
  servantRoom: boolean;
  poojaRoom: boolean;
  studyRoom: boolean;
  storeRoom: boolean;

  /** Residential + Rent only. */
  allowedFor: string;
  petFriendly: string;

  // Commercial
  washrooms: string;
  floorHeight: string;
  powerLoad: string;
  /**
   * The per-property-type numeric fields from `COMMERCIAL_CONFIGS`, keyed by
   * the exact name they are submitted under inside `features`.
   *
   * A bag rather than named fields because the set changes with the property
   * type — eight types with five fields each would be forty mostly-unused
   * columns on this interface, and every one of them would have to be added
   * here whenever the website adds a config.
   */
  commercialConfig: Record<string, string>;

  parkingCovered: string;
  parkingOpen: string;
  reraId: string;

  /**
   * `YYYY-MM-DD`, or empty. A text field rather than a native date picker:
   * no date-picker module is installed and adding one is its own
   * native-module decision (HANDOFF §5.1), not a default this form forces.
   * Schema type is `Date`, so the backend parses the string.
   */
  availableFrom: string;

  /** `legal.*` booleans the website collects and mobile previously could not. */
  occupancyCertificate: boolean;
  tradeLicense: boolean;
  fireNoc: boolean;

  /** Free-text landmarks, stored as `address.nearby: [String]`. */
  nearby: string[];

  amenities: string[];
}

export const EMPTY_LISTING_FORM: ListingFormValues = {
  categoryName: 'Residential',
  propertyTypeName: '',
  listingType: 'Sale',
  title: '',
  description: '',
  addressLine: '',
  city: '',
  locality: '',
  state: '',
  pincode: '',
  landmark: '',
  price: '',
  negotiable: false,
  deposit: '',
  maintenance: '',
  securityDeposit: '',
  totalSqft: '',
  carpetSqft: '',
  builtUpSqft: '',
  superBuiltUpSqft: '',
  plotSqft: '',
  latitude: '',
  longitude: '',
  gstApplicable: false,
  bookingAmount: '',
  maintenanceIncluded: true,
  commercialSubType: '',
  videoUrl: '',
  bhkType: '',
  bhk: '',
  bedrooms: '',
  bathrooms: '1',
  balconies: '0',
  furnishing: 'Unfurnished',
  propertyAge: 'New',
  floorNo: '',
  totalFloors: '',
  facing: '',
  constructionStatus: 'Ready to Move',
  servantRoom: false,
  poojaRoom: false,
  studyRoom: false,
  storeRoom: false,
  allowedFor: 'Family',
  petFriendly: 'No',
  washrooms: '1',
  floorHeight: '',
  powerLoad: '',
  commercialConfig: {},
  parkingCovered: '',
  parkingOpen: '',
  reraId: '',
  availableFrom: '',
  occupancyCertificate: false,
  tradeLicense: false,
  fireNoc: false,
  nearby: [],
  amenities: [],
};

/** One picked-or-existing image in the form's photo step. */
export interface ListingImage {
  /** Local file URI for a newly picked photo not yet uploaded. */
  localUri?: string;
  /** Cloudinary URL for a photo the listing already has. */
  remoteUrl?: string;
}

/**
 * A photo tagged with the room/area it belongs to, matching
 * `PropertyCategorizedImages`'s bucket keys (`types/backend/property.ts`).
 * `uri` is a local `file://` URI for a newly picked photo, or a Cloudinary
 * URL for one the listing already has — the two are handled by different
 * code in `formData.ts` and are never mixed in the same array.
 */
export interface CategorizedPhoto {
  uri: string;
  category: string;
}

/**
 * Category keys, one list per `categoryName`. Values are the exact schema
 * keys `PropertyCategorizedImages.residential`/`.commercial` accept — see
 * `types/backend/property.ts`. `other` is last in both: every other option
 * names a specific room, this one is the deliberate fallback.
 */
export const RESIDENTIAL_PHOTO_CATEGORIES = [
  { label: 'Exterior', value: 'exterior' },
  { label: 'Living room', value: 'livingRoom' },
  { label: 'Hall', value: 'hall' },
  { label: 'Dining area', value: 'diningArea' },
  { label: 'Kitchen', value: 'kitchen' },
  { label: 'Bedroom', value: 'bedroom' },
  { label: 'Bathroom', value: 'bathroom' },
  { label: 'Balcony', value: 'balcony' },
  { label: 'Study room', value: 'studyRoom' },
  { label: 'Pooja room', value: 'poojaRoom' },
  { label: 'Garden', value: 'garden' },
  { label: 'Parking', value: 'parking' },
  { label: 'Floor plan', value: 'floorPlan' },
  { label: 'Other', value: 'other' },
] as const;

export const COMMERCIAL_PHOTO_CATEGORIES = [
  { label: 'Facade', value: 'facade' },
  { label: 'Reception', value: 'reception' },
  { label: 'Work area', value: 'workArea' },
  { label: 'Cabin', value: 'cabin' },
  { label: 'Conference room', value: 'conferenceRoom' },
  { label: 'Shop floor', value: 'shopFloor' },
  { label: 'Display area', value: 'displayArea' },
  { label: 'Seating area', value: 'seatingArea' },
  { label: 'Kitchen', value: 'kitchenCommercial' },
  { label: 'Pantry', value: 'pantry' },
  { label: 'Washroom', value: 'washroom' },
  { label: 'Warehouse', value: 'warehouse' },
  { label: 'Loading area', value: 'loadingArea' },
  { label: 'Storage', value: 'storageArea' },
  { label: 'Parking', value: 'parking' },
  { label: 'Floor plan', value: 'floorPlan' },
  { label: 'Other', value: 'other' },
] as const;

export function photoCategoriesFor(
  category: ListingCategory
): readonly { label: string; value: string }[] {
  return category === 'Commercial' ? COMMERCIAL_PHOTO_CATEGORIES : RESIDENTIAL_PHOTO_CATEGORIES;
}

export function photoCategoryLabel(category: ListingCategory, value: string): string {
  return photoCategoriesFor(category).find((opt) => opt.value === value)?.label ?? 'Other';
}
