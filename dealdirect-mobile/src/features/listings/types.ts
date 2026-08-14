/**
 * The owner add/edit listing form's internal shape.
 *
 * This is NOT the wire format. `add` and `edit` submit through genuinely
 * different backend code paths with different field-name and image-handling
 * rules (see `formData.ts`); this shape is what the multi-step form and its
 * zod schema work with, converted at submit time.
 */

export type ListingCategory = 'Residential' | 'Commercial';

export const RESIDENTIAL_TYPES = [
  'Apartment / Flat',
  'Independent House / Villa',
  'Plot / Land',
  'Penthouse',
  'Studio Apartment',
  'Farmhouse',
] as const;

export const COMMERCIAL_TYPES = [
  'Office Space',
  'Shop / Showroom',
  'Warehouse / Godown',
  'Industrial Shed',
  'Co-working Space',
  'Commercial Plot',
] as const;

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

  // Residential
  bhk: string;
  bedrooms: string;
  bathrooms: string;
  balconies: string;
  furnishing: string;
  totalFloors: string;
  facing: string;
  constructionStatus: string;
  servantRoom: boolean;
  poojaRoom: boolean;
  studyRoom: boolean;
  storeRoom: boolean;

  // Commercial
  washrooms: string;
  pantry: string;
  meetingRooms: string;

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
  bhk: '',
  bedrooms: '',
  bathrooms: '',
  balconies: '',
  furnishing: '',
  totalFloors: '',
  facing: '',
  constructionStatus: '',
  servantRoom: false,
  poojaRoom: false,
  studyRoom: false,
  storeRoom: false,
  washrooms: '',
  pantry: '',
  meetingRooms: '',
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
