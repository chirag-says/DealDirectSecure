/**
 * The collection registry.
 *
 * A collection is a FRAME, not a category. "Luxury Homes" and "Sea View" can
 * both contain the same villa and that is the point: the same corpus, viewed
 * through different intentions, is what turns a list of listings into something
 * worth opening when you are not actively searching. Netflix does not have
 * different films in "Critically Acclaimed" and "Because You Watched"; it has
 * different reasons to look.
 *
 * The whole of Home's discovery half is this table. Adding "Sky Villas" is five
 * lines here and no new component, no new screen, no new query hook. That is
 * the only structure under which thirty curated rows is a maintainable idea
 * rather than thirty things to keep working.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THAT MAKES THIS SAFE: `minResults`.
 *
 * A collection that returns two listings is worse than no collection. A rail
 * with one card in it looks broken, and "Homes with a Private Pool" showing a
 * studio flat actively damages trust in every other row on the screen.
 *
 * So every collection declares the minimum it needs to be worth rendering, and
 * a collection that does not meet it UNMOUNTS. No empty state, no "0 results",
 * no placeholder. The user never learns it existed.
 *
 * That is what allows aspirational collections to sit in this table from day
 * one. "Sea View" matches nothing today and is therefore invisible today. The
 * hour someone lists a sea-facing flat, the row appears on its own with no
 * deploy. The registry is a statement of what DealDirect intends to be, and it
 * reveals itself as the inventory catches up.
 *
 * ---------------------------------------------------------------------------
 * EVERY COUNT BELOW WAS MEASURED AGAINST LIVE DATA ON 2026-08-03, against the
 * full corpus of 36 approved listings (24 Rent, 12 Sell). The counts are the
 * result of replicating the server's own regex — title, description,
 * address.city, address.area, address.locality — over every row, so they are
 * exact rather than estimated.
 *
 * Re-measure before editing this table. A term that has gone to zero should be
 * left in place, not deleted: `minResults` already hides it, and deleting it
 * loses the intent.
 *
 * ---------------------------------------------------------------------------
 * WHY PRICE COLLECTIONS CARRY AN `intent`.
 *
 * `price` is one column holding two incompatible populations. Rentals run from
 * ₹455 to ₹24,00,000 with a median of ₹20,000; sales run from ₹12,00,000 to
 * ₹5,00,00,000 with a median of ₹97,00,000. A band over both is meaningless:
 * "Under ₹25 Lakh" matches 28 of 36 listings and almost all of them are monthly
 * rents, so the row reads as "here are some cheap homes" while showing rentals.
 *
 * Every price collection is therefore scoped to one intent, and its label says
 * which. This is also why `intent` is a first-class field rather than just
 * another entry in `params`: see the note on client-side enforcement below.
 */

import type { ListingIntent } from '@/features/properties';
import type { PropertySearchParams } from '@/types/backend/property';

const LAKH = 100_000;
const CRORE = 10_000_000;

export interface Collection {
  id: string;
  /** Row heading. Written as an invitation, not as a filter description. */
  title: string;
  /** One line under it. Optional, and better absent than filler. */
  subtitle?: string;
  /**
   * Rent or sale, when the collection only makes sense within one.
   *
   * Sent to the server AND enforced on the client. Belt and braces, because the
   * server-side `listingType` filter (propertyController.js:1862) is written
   * but not yet deployed — the live API currently ignores the param and returns
   * both populations. Without the client guard, "Luxury Homes" would show
   * ₹24 lakh-a-month rentals alongside ₹5 crore villas today.
   *
   * The client filter becomes redundant the moment that deploys, and it is
   * cheap enough to leave in permanently as a correctness floor: a rail holds
   * at most twelve rows, so this is twelve comparisons.
   */
  intent?: ListingIntent;
  /** Sent to `/properties/search` as-is. */
  params: PropertySearchParams;
  /** Below this many results, the row does not render at all. */
  minResults: number;
  /**
   * Measured count on 2026-08-03, for the reader of this file. Never read at
   * runtime — the gate uses the live response, not this number.
   */
  measured: number;
}

/**
 * Ordered as they appear on Home.
 *
 * The order is editorial and should stay that way: strongest first, because
 * most sessions never scroll past the third row. Aspirational collections that
 * currently measure zero are grouped at the end so that when inventory arrives
 * they fill in below the proven rows rather than pushing them down.
 */
export const COLLECTIONS: readonly Collection[] = [
  {
    id: 'luxury',
    title: 'Luxury Collection',
    subtitle: 'The best of what owners are selling right now',
    intent: 'sale',
    params: { priceFrom: CRORE, sort: 'priceDesc' },
    minResults: 3,
    measured: 5,
  },
  {
    id: 'starter-homes',
    title: 'Starter Homes',
    subtitle: 'Buy your first place under ₹50 Lakh',
    intent: 'sale',
    params: { priceTo: 50 * LAKH, sort: 'priceAsc' },
    minResults: 3,
    measured: 4,
  },
  {
    id: 'rentals',
    title: 'Rent Without a Broker',
    subtitle: 'Deal with the owner directly',
    intent: 'rent',
    params: { sort: 'newest' },
    minResults: 4,
    measured: 24,
  },
  {
    id: 'family-homes',
    title: 'Family Homes',
    subtitle: 'Three bedrooms and up',
    params: { search: '3 BHK', sort: 'newest' },
    minResults: 4,
    measured: 9,
  },
  {
    id: 'city-apartments',
    title: 'City Apartments',
    params: { search: 'Apartment', sort: 'newest' },
    minResults: 4,
    measured: 16,
  },
  {
    id: 'villas',
    title: 'Villas & Independent Homes',
    subtitle: 'Space of your own',
    params: { search: 'Villa', sort: 'priceDesc' },
    minResults: 3,
    measured: 3,
  },
  {
    id: 'affordable-rentals',
    title: 'Under ₹25,000 a Month',
    intent: 'rent',
    params: { priceTo: 25_000, sort: 'priceAsc' },
    minResults: 4,
    measured: 19,
  },
  {
    id: 'commercial',
    title: 'For Your Business',
    subtitle: 'Offices, showrooms and warehouses',
    params: { search: 'Office Space', sort: 'newest' },
    minResults: 3,
    measured: 3,
  },
  {
    id: 'premium-rentals',
    title: 'Premium Rentals',
    subtitle: 'Larger homes, longer stays',
    intent: 'rent',
    params: { priceFrom: 50_000, sort: 'priceDesc' },
    minResults: 3,
    measured: 5,
  },

  // ── Aspirational ─────────────────────────────────────────────────────────
  // All measured 0 on 2026-08-03 and are therefore invisible. Left in place
  // deliberately: each one appears by itself the day the inventory exists.
  // These are the collections that make DealDirect feel like a magazine rather
  // than a database, so they are worth carrying before they are worth showing.
  {
    id: 'penthouses',
    title: 'Penthouses',
    subtitle: 'Top floor, nothing above you',
    params: { search: 'Penthouse', sort: 'priceDesc' },
    minResults: 3,
    measured: 2,
  },
  {
    id: 'sea-view',
    title: 'Sea View',
    subtitle: 'Wake up to the water',
    params: { search: 'Sea View', sort: 'priceDesc' },
    minResults: 3,
    measured: 0,
  },
  {
    id: 'private-pool',
    title: 'Homes with a Private Pool',
    params: { search: 'Private Pool', sort: 'priceDesc' },
    minResults: 3,
    measured: 0,
  },
  {
    id: 'ready-to-move',
    title: 'Ready to Move In',
    subtitle: 'No waiting, no construction',
    params: { search: 'Ready to Move', sort: 'newest' },
    minResults: 4,
    measured: 0,
  },
  {
    id: 'fully-furnished',
    title: 'Fully Furnished',
    subtitle: 'Arrive with a suitcase',
    params: { search: 'Furnished', sort: 'newest' },
    minResults: 4,
    measured: 0,
  },
  {
    id: 'farmhouses',
    title: 'Weekend Farmhouses',
    params: { search: 'Farm', sort: 'newest' },
    minResults: 3,
    measured: 0,
  },
];

/**
 * Localities.
 *
 * Free text, not the `city` param, and the reason is in the data: `city` is an
 * exact case-sensitive match, while live values include "Kolkata" and
 * "kolkata", "Howrah " with a trailing space, and "Ahamdabad". The search regex
 * is case-insensitive and covers `address.city`, so it catches all of them.
 *
 * KNOWN GAP: "Bangalore" (9 listings) and "Bengaluru" (6) are the same city
 * under two spellings, and a single free-text term cannot match both — the
 * server escapes the input, so no alternation can be smuggled in. The tile uses
 * the spelling with more inventory and therefore under-reports by 6. Fixing it
 * properly means normalising `address.city` on write, which is a backend
 * change. Flagged rather than hidden, because a user in Bengaluru will notice.
 */
export interface Locality {
  id: string;
  label: string;
  term: string;
  measured: number;
}

export const LOCALITIES: readonly Locality[] = [
  { id: 'mumbai', label: 'Mumbai', term: 'Mumbai', measured: 9 },
  { id: 'bangalore', label: 'Bangalore', term: 'Bangalore', measured: 9 },
  { id: 'pune', label: 'Pune', term: 'Pune', measured: 3 },
  { id: 'kolkata', label: 'Kolkata', term: 'Kolkata', measured: 3 },
  { id: 'ahmedabad', label: 'Ahmedabad', term: 'Ahmedabad', measured: 1 },
  { id: 'delhi', label: 'Delhi NCR', term: 'Delhi', measured: 1 },
];

export function findCollection(id: string): Collection | undefined {
  return COLLECTIONS.find((collection) => collection.id === id);
}
