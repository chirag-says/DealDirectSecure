/**
 * The property shape the UI consumes.
 *
 * The backend `Property` has roughly eighty fields, half of which apply only to
 * residential listings and half only to commercial, several typed `Mixed`, and a
 * `listingType` with six spellings of three meanings. Letting that reach a
 * component means every component re-derives the same fallbacks and one of them
 * eventually gets it wrong.
 *
 * So: one adapter, one flat summary, and components that render fields instead
 * of resolving them. The full detail model is M4's problem and will be a
 * different type; this one carries only what a card and a list row need.
 */

import type { Property } from '@/types/backend/property';

export type ListingIntent = 'rent' | 'sale';

export interface PropertyCoordinates {
  lat: number;
  lng: number;
}

export interface PropertySummary {
  id: string;
  /** The raw title. Used for accessibility labels and the detail screen. */
  title: string;
  /**
   * The title, but ONLY when it carries information the card does not already
   * show. Undefined for the auto-generated pattern.
   *
   * `AddPropertyContent.generateTitle()` composes titles as
   * `<BHK> <propertyTypeName> for <Rent|Sale> in <locality>`, which is exactly
   * the price line, the location line and the spec line concatenated. Rendering
   * it alongside them prints every fact twice. A hand-written title is worth
   * showing; a mechanical restatement is not.
   */
  headline?: string;

  /** Price in rupees, exactly as stored. See the adapter for why `priceUnit`
   *  is not applied to it. */
  priceRupees: number;
  /** Carried for the detail screen's "Monthly" / "Total" label only. It is NOT
   *  a unit multiplier and must never be treated as one. */
  priceUnit?: string;
  negotiable: boolean;

  /** Normalised from the six accepted casings. `null` when unset or unknown. */
  intent: ListingIntent | null;

  coverImage?: string;
  imageCount: number;

  city?: string;
  locality?: string;
  /** Pre-composed "Locality, City", already collapsed if either is missing. */
  locationLabel: string;

  categoryName?: string;
  subcategoryName?: string;
  propertyTypeName?: string;

  bhk?: string;
  bedrooms?: number;
  bathrooms?: number;
  /** Best available area figure, in sqft, across the five area fields. */
  areaSqft?: number;

  /** One of `Unfurnished | Semi-furnished | Fully furnished`, per the add/edit
   *  form. See `features/search/filters.ts` for the filter that reads it. */
  furnishing?: string;
  /** Free text, e.g. "Ready to move". No fixed value set — see
   *  `features/search/filters.ts`'s CONSTRUCTION STATUS note. */
  constructionStatus?: string;

  /**
   * `null` for a large share of listings: both `address.latitude` and
   * `address.longitude` are optional and the backend only promotes them to the
   * top level when BOTH are present. The map surface in M4 must state how many
   * results it could not place rather than dropping a pin at (0, 0).
   */
  coordinates: PropertyCoordinates | null;

  /**
   * Detail-screen opens, as counted by the backend.
   *
   * The single behavioural signal in this system. No list endpoint can sort by
   * it, so ranking on it has to happen client-side; `usePopularListings`
   * documents the consequences of that.
   */
  views: number;

  createdAt?: string;
}

// --- Detail ---------------------------------------------------------------

/**
 * One image, with the room it belongs to.
 *
 * `categorizedImages` is a nested object of arrays keyed by room type, and the
 * flat `images[]` array is separate from it. Flattened once here so no gallery
 * component walks that shape.
 */
export interface GalleryImage {
  uri: string;
  /**
   * Display label for the bucket ("Living room", "Loading area").
   * Undefined for entries from the flat `images[]` array, which carry no room.
   */
  label?: string;
  /** Bucket key, retained so the gallery screen can group without re-parsing. */
  bucket?: string;
}

/**
 * The owner, as `GET /properties/:id` populates them.
 *
 * `name email phone profileImage` only. Every field is optional: the populate
 * succeeds even when the underlying user row is missing them, and `owner`
 * itself is absent on listings whose owner account was deleted.
 */
export interface PropertyOwnerContact {
  id: string;
  name?: string;
  phone?: string;
  email?: string;
  profileImage?: string;
}

/**
 * The full listing, for the detail screen.
 *
 * Extends `PropertySummary` so every fallback the card resolved is resolved the
 * same way here, and adds the fields only a detail view needs.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS CARRIES `raw`
 *
 * The schema has roughly eighty fields, split into a residential and a
 * commercial set that never both apply, most of them plain scalars needing no
 * normalisation at all. Copying them into a parallel interface would be eighty
 * lines of restatement that has to be kept in sync with the backend by hand,
 * and the field-map renderer would then read the copy instead of the source.
 *
 * So the adapter lifts what genuinely needs deciding — the six-spelling intent,
 * the five area fields, the two coordinate sources, the two image shapes — and
 * the declarative field map reads the rest straight off `raw` through a spec.
 * One engine, one source, no hand-maintained mirror.
 *
 * `raw` is for the field map. Anything a component reads directly and
 * repeatedly should be lifted onto this interface instead.
 */
export interface PropertyDetail extends PropertySummary {
  description?: string;
  videoUrl?: string;

  /** Flat `images[]` first, then every categorised bucket in schema order. */
  gallery: GalleryImage[];
  amenities: string[];

  owner: PropertyOwnerContact | null;

  addressLine?: string;
  state?: string;
  pincode?: string;
  landmark?: string;
  /** `address.nearby` — landmarks/points of interest the owner listed. Typed
   *  and carried since M4 but never rendered until M16. */
  nearby: string[];

  availableFrom?: string;
  status?: string;

  /**
   * The backend document, for the declarative field map only. See the note
   * above before reaching into it from a component.
   */
  raw: Property;
}
