/**
 * The server's shortlist projection into the row the UI draws.
 *
 * The shortlist endpoints send card fields only, not the ~80-field property
 * document, so this adapter is small and does not go through
 * `adaptProperty` — there is nothing here for it to resolve. What it does
 * share is `normalizeListingType`, because the six spellings of three meanings
 * are the same six spellings on this projection as everywhere else, and a
 * second implementation would be a second bug.
 */

import { normalizeListingType, type RailProperty } from '@/features/properties';
import type { ComparableProperty } from '@/features/search';
import type { PropertyCategorizedImages } from '@/types/backend/property';
import type { ShortlistCardProperty, ShortlistEntry } from '@/types/backend/shortlist';
import type { StoredShortlistEntry } from './store';
import type { ShortlistItem } from './types';

/** First image in any categorised bucket, for a listing with no flat `images`. */
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

export function adaptShortlistProperty(property: ShortlistCardProperty): RailProperty {
  const locationLabel = [property.locality, property.city].filter(Boolean).join(', ');

  return {
    id: property._id,
    title: property.title ?? 'Property',
    priceRupees: property.price ?? 0,
    intent: normalizeListingType(property.listingType),
    coverImage: property.images?.[0] ?? firstCategorizedImage(property.categorizedImages),
    locationLabel,
    bhk: property.bhk,
    propertyTypeName: property.propertyTypeName,
    areaSqft: typeof property.area === 'number' && property.area > 0 ? property.area : undefined,
  };
}

/**
 * `addedAt` is an ISO string on the wire and epoch ms in the store, because
 * the store's ordering has always been numeric and a string comparison would
 * quietly work until a timezone offset showed up in one of them.
 */
export function adaptShortlistEntry(entry: ShortlistEntry): ShortlistItem {
  const addedAt = Date.parse(entry.addedAt);

  return {
    entryId: entry.id,
    property: adaptShortlistProperty(entry.property),
    shortlistedAt: Number.isNaN(addedAt) ? Date.now() : addedAt,
    note: entry.note || undefined,
    available: entry.available !== false,
    unavailableReason: entry.unavailableReason ?? null,
  };
}

/** The same row, on its way into the offline cache. */
export function itemToStoredEntry(item: ShortlistItem): StoredShortlistEntry {
  return {
    entryId: item.entryId,
    property: item.property,
    shortlistedAt: item.shortlistedAt,
    note: item.note,
    available: item.available,
    unavailableReason: item.unavailableReason,
  };
}

/**
 * A shortlist row as a comparison column.
 *
 * `ComparableProperty` rather than `PropertySummary` on purpose: this
 * projection genuinely does not know whether a price is negotiable, how many
 * people have viewed the listing, or where it is on a map. Leaving those
 * absent makes the comparison table print an em dash, which is true; widening
 * them to defaults would make it print "No", which is not.
 *
 * The type-only import keeps this a compile-time relationship — nothing from
 * `features/search` is loaded at runtime by the shortlist.
 */
export function shortlistItemToComparable(item: ShortlistItem): ComparableProperty {
  const { property } = item;

  return {
    id: property.id,
    title: property.title,
    priceRupees: property.priceRupees,
    intent: property.intent,
    coverImage: property.coverImage,
    locationLabel: property.locationLabel,
    bhk: property.bhk,
    bedrooms: property.bedrooms,
    bathrooms: property.bathrooms,
    areaSqft: property.areaSqft,
    propertyTypeName: property.propertyTypeName,
    subcategoryName: property.subcategoryName,
  };
}
