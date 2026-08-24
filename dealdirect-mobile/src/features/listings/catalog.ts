/**
 * The add-property vocabulary, mirrored from the website's form.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 *
 * `client-next/src/app/add-property/AddPropertyContent.jsx` is a single 2047
 * line file holding its constants, its six steps, its geocoding and its submit
 * together. Mobile's form was built independently and had drifted: it offered
 * twelve property types where the website offers sixteen, one flat amenity list
 * where the website has two, one pair of photo categories where the website has
 * sixteen sets, and none of the commercial configuration at all.
 *
 * Everything the two clients must AGREE on lives here, as data, so the drift is
 * visible in one place instead of spread through a form component. The option
 * strings are exact: they are submitted verbatim as `propertyTypeName`,
 * `categoryName`, `features.*` and the `categorizedImages` bucket keys, and the
 * server matches them with no case folding and no nearest match.
 *
 * The property TYPE list is deliberately NOT here — see `taxonomy.ts`. It comes
 * from the server, because it is the one part of this vocabulary the server
 * validates strictly and is mid-migration on.
 */

import type { ListingCategory } from './types';

/** `bhkType` on the website. Sent as `features.bhk`. */
export const BHK_OPTIONS = [
  '1 RK',
  '1 BHK',
  '2 BHK',
  '3 BHK',
  '4 BHK',
  '5+ BHK',
  'Studio',
] as const;

/** `commercialSubType`. Commercial only. */
export const COMMERCIAL_SUBTYPES = ['Bare Shell', 'Warm Shell', 'Fully Furnished'] as const;

export const FURNISHING_OPTIONS = ['Unfurnished', 'Semi-Furnished', 'Fully Furnished'] as const;

export const PROPERTY_AGE_OPTIONS = ['New', '1-5 Years', '5-10 Years', '10+ Years'] as const;

/** Residential + Sell only, matching the website's conditional. */
export const CONSTRUCTION_STATUS_OPTIONS = [
  'Ready to Move',
  'Under Construction',
  'New Launch',
] as const;

export const FACING_OPTIONS = [
  'East',
  'West',
  'North',
  'South',
  'North-East',
  'North-West',
  'South-East',
  'South-West',
] as const;

/** `allowedFor`. Residential + Rent only. */
export const TENANT_OPTIONS = [
  'Family',
  'Bachelor Male',
  'Bachelor Female',
  'Company Lease',
  'Any',
] as const;

/**
 * Two lists, not one.
 *
 * Mobile had a single twelve-item list used for both categories, so a warehouse
 * was offered a Swimming Pool and never offered a Loading Dock.
 */
export const RESIDENTIAL_AMENITIES = [
  'Lift',
  'Gym',
  'Swimming Pool',
  'Club House',
  'Power Backup',
  'CCTV',
  'Parking Covered',
  'Parking Open',
  'Modular Kitchen',
  'Wardrobes',
  'Geyser',
  'AC',
  'Fans',
  'Water Purifier',
  'Intercom',
  'Garden',
  'Jogging Track',
  'Kids Play Area',
  'Community Hall',
  'RO Water',
  'Store Room',
  'Servant Room',
] as const;

export const COMMERCIAL_AMENITIES = [
  'Lift',
  'Power Backup',
  'CCTV',
  'Fire Safety',
  'Reserved Parking',
  'Visitor Parking',
  'Internet',
  'Loading Dock',
  'Goods Lift',
  'Sprinkler System',
  'Water Storage',
  'Security',
  'Washrooms',
  'AC',
] as const;

export function amenitiesFor(category: ListingCategory): readonly string[] {
  return category === 'Commercial' ? COMMERCIAL_AMENITIES : RESIDENTIAL_AMENITIES;
}

/**
 * Per-property-type numeric configuration, Commercial only.
 *
 * Keys are submitted flat inside `features`, exactly as spelled. Labels are
 * written out rather than derived from the key: the website generates them with
 * a regex, which produces "Office Space" for `officeSpace` inside a Warehouse
 * card where it means "office space within the shed" — writing them makes the
 * meaning explicit and survives a key rename.
 */
export interface CommercialConfig {
  label: string;
  fields: readonly { key: string; label: string }[];
}

export const COMMERCIAL_CONFIGS: Readonly<Record<string, CommercialConfig>> = {
  'Office Space': {
    label: 'Office Configuration',
    fields: [
      { key: 'workstations', label: 'Workstations' },
      { key: 'conferenceRooms', label: 'Conference rooms' },
      { key: 'cabins', label: 'Cabins' },
      { key: 'washrooms', label: 'Washrooms' },
      { key: 'pantry', label: 'Pantry' },
    ],
  },
  'Shop / Retail': {
    label: 'Shop Configuration',
    fields: [
      { key: 'frontage', label: 'Frontage (ft)' },
      { key: 'washrooms', label: 'Washrooms' },
      { key: 'storage', label: 'Storage' },
      { key: 'displayWindows', label: 'Display windows' },
    ],
  },
  Showroom: {
    label: 'Showroom Configuration',
    fields: [
      { key: 'frontage', label: 'Frontage (ft)' },
      { key: 'washrooms', label: 'Washrooms' },
      { key: 'storage', label: 'Storage' },
      { key: 'displayArea', label: 'Display area (sq.ft)' },
      { key: 'parking', label: 'Parking' },
    ],
  },
  'Restaurant / Cafe': {
    label: 'Restaurant Configuration',
    fields: [
      { key: 'seatingCapacity', label: 'Seating capacity' },
      { key: 'kitchenArea', label: 'Kitchen area (sq.ft)' },
      { key: 'washrooms', label: 'Washrooms' },
      { key: 'barArea', label: 'Bar area (sq.ft)' },
      { key: 'outdoorSeating', label: 'Outdoor seating' },
    ],
  },
  'Co-Working Space': {
    label: 'Co-Working Configuration',
    fields: [
      { key: 'workstations', label: 'Workstations' },
      { key: 'meetingRooms', label: 'Meeting rooms' },
      { key: 'privateCabins', label: 'Private cabins' },
      { key: 'phoneBooths', label: 'Phone booths' },
      { key: 'loungeArea', label: 'Lounge area (sq.ft)' },
    ],
  },
  'Warehouse / Godown': {
    label: 'Warehouse Configuration',
    fields: [
      { key: 'loadingDocks', label: 'Loading docks' },
      { key: 'ceilingHeight', label: 'Ceiling height (ft)' },
      { key: 'floorLoadCapacity', label: 'Floor load capacity' },
      { key: 'officeSpace', label: 'Office space (sq.ft)' },
      { key: 'washrooms', label: 'Washrooms' },
    ],
  },
  'Industrial Shed': {
    label: 'Industrial Shed Configuration',
    fields: [
      { key: 'ceilingHeight', label: 'Ceiling height (ft)' },
      { key: 'floorLoadCapacity', label: 'Floor load capacity' },
      { key: 'powerConnection', label: 'Power connection (kW)' },
      { key: 'overheadCrane', label: 'Overhead crane' },
      { key: 'officeSpace', label: 'Office space (sq.ft)' },
    ],
  },
  'Commercial Building / Floor': {
    label: 'Building Configuration',
    fields: [
      { key: 'washrooms', label: 'Washrooms' },
      { key: 'pantry', label: 'Pantry' },
      { key: 'centralAC', label: 'Central AC' },
      { key: 'powerBackup', label: 'Power backup' },
      { key: 'parking', label: 'Parking' },
    ],
  },
};

/**
 * Photo categories, per property type.
 *
 * `key` is the exact bucket name under `categorizedImages.residential` or
 * `.commercial` in the Property schema, so these are wire values rather than
 * labels. `max` mirrors the website's per-category cap.
 *
 * Mobile previously had one residential list and one commercial list shared by
 * every type, which meant a Studio was asked for a Building Exterior it does
 * not have and a Warehouse was asked for a Bedroom.
 */
export interface PhotoCategory {
  key: string;
  label: string;
  max: number;
  tip?: string;
}

const RESIDENTIAL_FALLBACK = 'Apartment / Flat';
const COMMERCIAL_FALLBACK = 'Office Space';

const RESIDENTIAL_PHOTO_SETS: Record<string, readonly PhotoCategory[]> = {
  'Apartment / Flat': [
    { key: 'exterior', label: 'Building Exterior', max: 3, tip: 'Show the building facade and entrance' },
    { key: 'livingRoom', label: 'Living Room', max: 4, tip: 'Main living area with natural lighting' },
    { key: 'bedroom', label: 'Bedroom(s)', max: 4, tip: 'All bedrooms - master and other rooms' },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3, tip: 'Attached and common bathrooms' },
    { key: 'kitchen', label: 'Kitchen', max: 2, tip: 'Kitchen with appliances visible' },
    { key: 'balcony', label: 'Balcony / Terrace', max: 2, tip: 'Balcony view and space' },
    { key: 'hall', label: 'Hall / Lobby', max: 2, tip: 'Building lobby or common areas' },
    { key: 'parking', label: 'Parking Area', max: 2, tip: 'Covered or open parking space' },
    { key: 'floorPlan', label: 'Floor Plan', max: 1, tip: '2D layout if available' },
    { key: 'other', label: 'Other Areas', max: 5, tip: 'Amenities, garden, pool, etc.' },
  ],
  'Independent House': [
    { key: 'exterior', label: 'House Exterior', max: 4 },
    { key: 'livingRoom', label: 'Living Room', max: 3 },
    { key: 'bedroom', label: 'Bedroom(s)', max: 4 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'garden', label: 'Garden/Lawn', max: 3 },
    { key: 'parking', label: 'Parking', max: 2 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
  Villa: [
    { key: 'exterior', label: 'Villa Exterior', max: 5 },
    { key: 'livingRoom', label: 'Living Room', max: 4 },
    { key: 'bedroom', label: 'Bedroom(s)', max: 5 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'garden', label: 'Garden', max: 3 },
    { key: 'balcony', label: 'Balcony / Terrace', max: 3 },
    { key: 'parking', label: 'Parking', max: 2 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
  'Builder Floor': [
    { key: 'exterior', label: 'Building Exterior', max: 2 },
    { key: 'livingRoom', label: 'Living Room', max: 3 },
    { key: 'bedroom', label: 'Bedrooms', max: 4 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'balcony', label: 'Balcony', max: 2 },
    { key: 'parking', label: 'Parking', max: 2 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
  'Studio Apartment': [
    { key: 'livingRoom', label: 'Studio Space', max: 4 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'bathroom', label: 'Bathroom', max: 2 },
    { key: 'balcony', label: 'Balcony / Sit-out', max: 2 },
    { key: 'other', label: 'Other', max: 3 },
  ],
  Penthouse: [
    { key: 'exterior', label: 'Building & Terrace', max: 4 },
    { key: 'livingRoom', label: 'Living Area', max: 4 },
    { key: 'bedroom', label: 'Bedroom(s)', max: 4 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'balcony', label: 'Balcony / Terrace', max: 2 },
    { key: 'hall', label: 'Lobby / Passage', max: 2 },
    { key: 'parking', label: 'Parking', max: 2 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
  'Row House': [
    { key: 'exterior', label: 'House Exterior', max: 3 },
    { key: 'livingRoom', label: 'Living Room', max: 3 },
    { key: 'bedroom', label: 'Bedrooms', max: 4 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'garden', label: 'Garden / Front Yard', max: 3 },
    { key: 'parking', label: 'Parking', max: 2 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
  'Farm House': [
    { key: 'exterior', label: 'Property Exterior', max: 5 },
    { key: 'livingRoom', label: 'Living Space', max: 3 },
    { key: 'bedroom', label: 'Bedrooms / Guest Rooms', max: 4 },
    { key: 'bathroom', label: 'Bathroom(s)', max: 3 },
    { key: 'kitchen', label: 'Kitchen', max: 2 },
    { key: 'garden', label: 'Garden / Lawn', max: 5 },
    { key: 'parking', label: 'Parking / Driveway', max: 3 },
    { key: 'floorPlan', label: 'Floor / Site Plan', max: 1 },
    { key: 'other', label: 'Other', max: 5 },
  ],
};

const COMMERCIAL_PHOTO_SETS: Record<string, readonly PhotoCategory[]> = {
  'Office Space': [
    { key: 'facade', label: 'Building Exterior', max: 4 },
    { key: 'reception', label: 'Reception / Lobby', max: 3 },
    { key: 'workArea', label: 'Open Work Area', max: 6 },
    { key: 'cabin', label: 'Cabins / Private Rooms', max: 4 },
    { key: 'conferenceRoom', label: 'Conference / Meeting Rooms', max: 3 },
    { key: 'pantry', label: 'Pantry / Cafeteria', max: 3 },
    { key: 'washroom', label: 'Washrooms', max: 3 },
    { key: 'parking', label: 'Parking Area', max: 3 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Shop / Retail': [
    { key: 'facade', label: 'Shop Front / Facade', max: 4 },
    { key: 'shopFloor', label: 'Shop Floor', max: 6 },
    { key: 'displayArea', label: 'Display / Window Area', max: 4 },
    { key: 'storageArea', label: 'Back Storage / Inventory', max: 4 },
    { key: 'washroom', label: 'Washrooms', max: 2 },
    { key: 'parking', label: 'Customer Parking', max: 3 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  Showroom: [
    { key: 'facade', label: 'Showroom Exterior', max: 4 },
    { key: 'reception', label: 'Reception / Front Desk', max: 3 },
    { key: 'displayArea', label: 'Display Area', max: 6 },
    { key: 'seatingArea', label: 'Customer Seating / Lounge', max: 3 },
    { key: 'storageArea', label: 'Back Office / Storage', max: 3 },
    { key: 'parking', label: 'Parking', max: 3 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Restaurant / Cafe': [
    { key: 'facade', label: 'Exterior / Entrance', max: 4 },
    { key: 'seatingArea', label: 'Dining / Seating Area', max: 6 },
    { key: 'kitchenCommercial', label: 'Commercial Kitchen', max: 4 },
    { key: 'washroom', label: 'Washrooms', max: 3 },
    { key: 'storageArea', label: 'Storage / Prep Area', max: 3 },
    { key: 'parking', label: 'Parking / Valet Area', max: 3 },
    { key: 'floorPlan', label: 'Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Co-Working Space': [
    { key: 'facade', label: 'Exterior', max: 3 },
    { key: 'reception', label: 'Reception / Entry', max: 3 },
    { key: 'workArea', label: 'Open Desk Area', max: 6 },
    { key: 'cabin', label: 'Private Cabins', max: 4 },
    { key: 'conferenceRoom', label: 'Meeting / Conference Rooms', max: 3 },
    { key: 'seatingArea', label: 'Lounge / Breakout', max: 3 },
    { key: 'pantry', label: 'Pantry / Cafe', max: 3 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Warehouse / Godown': [
    { key: 'facade', label: 'Warehouse Exterior', max: 3 },
    { key: 'warehouse', label: 'Main Storage Area', max: 8 },
    { key: 'loadingArea', label: 'Loading / Unloading Area', max: 4 },
    { key: 'storageArea', label: 'Racks / Internal Storage', max: 4 },
    { key: 'parking', label: 'Truck / Vehicle Parking', max: 3 },
    { key: 'floorPlan', label: 'Site / Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Industrial Shed': [
    { key: 'facade', label: 'Shed Exterior', max: 3 },
    { key: 'warehouse', label: 'Main Production Floor', max: 8 },
    { key: 'loadingArea', label: 'Loading / Dock Area', max: 4 },
    { key: 'storageArea', label: 'Storage / Raw Material', max: 4 },
    { key: 'parking', label: 'Parking / Yard', max: 3 },
    { key: 'floorPlan', label: 'Layout / Floor Plan', max: 1 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
  'Commercial Building / Floor': [
    { key: 'facade', label: 'Building Exterior', max: 4 },
    { key: 'reception', label: 'Main Lobby / Reception', max: 3 },
    { key: 'workArea', label: 'Typical Floor / Work Area', max: 6 },
    { key: 'cabin', label: 'Cabins / Offices', max: 4 },
    { key: 'conferenceRoom', label: 'Conference Rooms', max: 3 },
    { key: 'parking', label: 'Parking Levels', max: 4 },
    { key: 'floorPlan', label: 'Floor Plan', max: 2 },
    { key: 'other', label: 'Other Areas', max: 5 },
  ],
};

/**
 * The photo categories for a given category + type, falling back the way the
 * website does: to `Apartment / Flat` or `Office Space` for a type with no set
 * of its own. The fallback matters more here than on the website, because the
 * type list is fetched and may contain a name this table has not seen.
 */
export function photoCategoriesForType(
  category: ListingCategory,
  propertyType: string
): readonly PhotoCategory[] {
  const sets = category === 'Commercial' ? COMMERCIAL_PHOTO_SETS : RESIDENTIAL_PHOTO_SETS;
  const fallback = category === 'Commercial' ? COMMERCIAL_FALLBACK : RESIDENTIAL_FALLBACK;
  return sets[propertyType] ?? sets[fallback] ?? [];
}

/**
 * Which bucket a categorised photo is filed under on the server.
 *
 * `Commercial` is the special case and everything else is residential-shaped,
 * the same rule the photo category table above applies, so a photo is always
 * filed under the bucket whose keys it was labelled with.
 */
export function photoBucketFor(category: ListingCategory): 'residential' | 'commercial' {
  return category === 'Commercial' ? 'commercial' : 'residential';
}
