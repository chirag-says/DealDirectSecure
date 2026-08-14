import type { Property } from '@/types/backend/property';
import { EMPTY_LISTING_FORM, type CategorizedPhoto, type ListingFormValues } from './types';

const asString = (value: unknown): string => (value === undefined || value === null ? '' : String(value));

export function propertyToFormValues(property: Property): ListingFormValues {
  const category: ListingFormValues['categoryName'] =
    property.categoryName === 'Commercial' ? 'Commercial' : 'Residential';

  return {
    ...EMPTY_LISTING_FORM,
    categoryName: category,
    propertyTypeName: property.propertyTypeName ?? '',
    listingType: /rent/i.test(property.listingType ?? '') ? 'Rent' : 'Sale',
    title: property.title ?? '',
    description: property.description ?? '',

    addressLine: property.address?.line ?? '',
    city: property.address?.city ?? property.city ?? '',
    locality: property.address?.area ?? property.locality ?? '',
    state: property.address?.state ?? '',
    pincode: property.address?.pincode ?? '',
    landmark: property.address?.landmark ?? '',

    price: asString(property.price),
    negotiable: property.negotiable ?? false,
    deposit: asString(property.deposit),
    maintenance: asString(property.maintenance),
    securityDeposit: asString(property.securityDeposit),

    totalSqft: asString(property.area?.totalSqft),
    carpetSqft: asString(property.area?.carpetSqft),
    builtUpSqft: asString(property.area?.builtUpSqft),
    superBuiltUpSqft: asString(property.area?.superBuiltUpSqft),
    plotSqft: asString(property.area?.plotSqft),
    // `area.pricePerSqft` is intentionally not read back: it is derived on
    // submit, so round-tripping it would let a stale value survive a price
    // change.

    bhk: property.bhk ?? '',
    bedrooms: asString(property.bedrooms),
    bathrooms: asString(property.bathrooms),
    balconies: asString(property.balconies),
    furnishing: property.furnishing ?? '',
    totalFloors: property.totalFloors ?? '',
    facing: property.facing ?? '',
    constructionStatus: property.constructionStatus ?? '',
    servantRoom: property.extras?.servantRoom ?? false,
    poojaRoom: property.extras?.poojaRoom ?? false,
    studyRoom: property.extras?.studyRoom ?? false,
    storeRoom: property.extras?.storeRoom ?? false,

    washrooms: asString(property.washrooms),
    pantry: property.pantry ?? '',
    meetingRooms: property.meetingRooms ?? '',

    parkingCovered: asString(property.parking?.covered),
    parkingOpen: asString(property.parking?.open),
    reraId: property.legal?.reraId ?? '',
    occupancyCertificate: property.legal?.occupancyCertificate ?? false,
    tradeLicense: property.legal?.tradeLicense ?? false,
    fireNoc: property.legal?.fireNoc ?? false,

    // Schema type is `Date`, so this arrives as an ISO string. The form wants
    // `YYYY-MM-DD`, which is its leading 10 characters.
    availableFrom: property.availableFrom ? String(property.availableFrom).slice(0, 10) : '',

    // Read back so an edit does not silently drop them, even though
    // `updateMyProperty` rebuilds `address` from flat fields and will not
    // persist a change — see `formData.ts`.
    nearby: property.address?.nearby ?? [],

    amenities: property.amenities ?? [],
  };
}

/**
 * Every photo the listing currently has, tagged with the category bucket key
 * it actually lives under. This is what `buildEditFormData` sends back as
 * `existingCategorizedImages` to avoid wiping the gallery — see the module
 * doc in `formData.ts` for why omitting a photo here deletes it, not just
 * hides it.
 *
 * Falls back to the flat `images[]` array (every entry tagged `other`) only
 * when the categorized buckets are empty — a listing added before this
 * feature, or added on mobile before per-room categorisation existed.
 */
export function existingCategorizedPhotos(property: Property): CategorizedPhoto[] {
  const bucket =
    property.categoryName === 'Commercial'
      ? property.categorizedImages?.commercial
      : property.categorizedImages?.residential;

  if (bucket) {
    const fromBucket: CategorizedPhoto[] = [];
    for (const [category, urls] of Object.entries(bucket)) {
      if (!Array.isArray(urls)) continue;
      for (const uri of urls) {
        if (uri) fromBucket.push({ uri, category });
      }
    }
    if (fromBucket.length > 0) return fromBucket;
  }

  return (property.images ?? []).map((uri) => ({ uri, category: 'other' }));
}
