/**
 * Query keys, in one place.
 *
 * Keys are declared centrally rather than inline at each hook so that
 * invalidation can be reasoned about by reading one file. A key written at its
 * call site is a key nobody else can safely invalidate.
 *
 * Shape: `[domain, operation, ...discriminators]`. The domain segment alone is
 * a valid prefix, so `queryClient.invalidateQueries({ queryKey: qk.properties })`
 * drops everything property-shaped without listing the operations.
 */

import type { PropertySearchParams } from '@/types/backend/property';
import type { ObjectId } from '@/types/backend/common';

/**
 * Search params, reduced to a stable key fragment.
 *
 * TanStack hashes keys with a key-sorted JSON serialiser, so object key order
 * is already safe. What is NOT safe is `undefined` versus absent: they hash
 * identically, but a param whose value is an empty string does not, and would
 * split the cache into two entries for the same query. So empties are dropped
 * here, and the same normaliser feeds the request itself.
 */
export function normalizeSearchParams(
  params: PropertySearchParams
): Record<string, string | number> {
  const entries = Object.entries(params).filter(
    ([, value]) => value !== undefined && value !== null && value !== ''
  ) as [string, string | number][];

  return Object.fromEntries(entries.sort(([a], [b]) => a.localeCompare(b)));
}

export const qk = {
  properties: ['properties'] as const,

  /** Infinite feed. `page` is deliberately excluded: it is the page param. */
  propertySearch: (params: PropertySearchParams) =>
    ['properties', 'search', normalizeSearchParams(params)] as const,

  /**
   * A Home collection rail: ONE page, not an infinite feed.
   *
   * Deliberately a different key namespace from `propertySearch` even when the
   * params coincide. TanStack keeps one cache entry per key, and an infinite
   * query stores `{ pages: [...] }` where a plain query stores the page object
   * itself. Sharing a key between the two shapes means whichever mounts second
   * reads the other's structure and throws.
   *
   * The collection id is part of the key so that two collections which happen
   * to resolve to the same params stay independently cacheable and separately
   * invalidatable.
   */
  collection: (id: string, params: PropertySearchParams) =>
    ['properties', 'collection', id, normalizeSearchParams(params)] as const,

  propertyDetail: (id: ObjectId) => ['properties', 'detail', id] as const,

  /**
   * Whether the signed-in user has expressed interest in one listing.
   *
   * Its own key rather than a field on the detail cache: the detail query is
   * public and shared by every viewer, while this is per-user and must be
   * dropped on logout. `AuthProvider` clears the whole client on logout, but
   * keeping them separate also means an interest toggle does not invalidate
   * the listing itself and re-spend a view count.
   */
  propertyInterest: (id: ObjectId) => ['properties', 'interest', id] as const,

  suggestions: (query: string) => ['properties', 'suggestions', query] as const,

  /**
   * The listings the user has expressed interest in.
   *
   * Under the `properties` domain because that is what it returns, and because
   * marking interest must invalidate it. Note this is the SAME data as
   * `propertyInterest`, seen from the other end: one asks "is this listing in
   * my list", the other asks "what is in my list". Both are invalidated by the
   * same toggle.
   */
  savedProperties: () => ['properties', 'saved'] as const,

  savedSearches: ['savedSearches'] as const,
  savedSearchList: () => ['savedSearches', 'mine'] as const,

  /**
   * The shortlist, now server-backed (Phase 1, F7).
   *
   * Two keys rather than one because they answer two different questions at
   * two different costs. `shortlistIds` is the cheap membership sync every
   * save button reads; `shortlistList` is the full card projection only the
   * Activity screen needs. A save invalidates the domain, so both refresh
   * together, but a screen that only needs membership never pays for the list.
   *
   * The device-local MMKV store is still the synchronous read model behind
   * both (it is the guest list AND the offline cache) — see
   * `features/shortlist/store.ts`. These keys own the network half.
   */
  shortlist: ['shortlist'] as const,
  shortlistList: () => ['shortlist', 'list'] as const,
  shortlistIds: () => ['shortlist', 'ids'] as const,
  /** Public, per token. Somebody else's list; nothing here is per-user. */
  shortlistShared: (token: string) => ['shortlist', 'shared', token] as const,

  /**
   * Locality price data (Phase 4, F18). Public and slow-moving — it is a
   * quarterly aggregate, so it is cached long and refetched rarely.
   */
  localities: (params: Record<string, string | number | undefined>) =>
    ['localities', 'list', params] as const,
  locality: (slug: string, listingType: string) => ['localities', slug, listingType] as const,
  /** The listing form's one comparison line. Keyed on every input that changes it. */
  priceGuidance: (params: Record<string, string | undefined>) =>
    ['localities', 'guidance', params] as const,

  notifications: ['notifications'] as const,
  notificationList: () => ['notifications', 'list'] as const,

  chat: ['chat'] as const,
  /**
   * `GET /chat/conversations`. Not paginated, one cache entry for the whole
   * list. `myUnreadCount` on each row is also where the Messages tab badge is
   * summed from — there is a dedicated `/chat/unread-count` endpoint, but it
   * computes the exact same sum server-side, so calling it too would just be
   * a second query key to keep in sync with this one for no new information.
   */
  chatConversations: () => ['chat', 'conversations'] as const,

  /**
   * A conversation thread's history. `page` is excluded for the same reason
   * `propertySearch` excludes it: it is the infinite-query page param, not a
   * cache discriminator.
   */
  chatMessages: (conversationId: ObjectId) => ['chat', 'messages', conversationId] as const,

  projects: ['projects'] as const,

  /** `GET /projects`. Separate domain from properties: different collection,
   *  different endpoint, invalidated independently. */
  projectList: (params: Record<string, string | number | boolean>) =>
    ['projects', 'list', params] as const,
  projectDetail: (id: ObjectId) => ['projects', 'detail', id] as const,
  unitTypesByProject: (projectId: ObjectId) => ['projects', 'unitTypes', projectId] as const,
  unitTypeDetail: (id: ObjectId) => ['projects', 'unitType', id] as const,
  campaignsByUnitType: (unitTypeId: ObjectId) => ['projects', 'campaigns', 'unitType', unitTypeId] as const,
  campaignDetail: (id: ObjectId) => ['projects', 'campaign', id] as const,
  myBookings: () => ['projects', 'bookings', 'mine'] as const,
  paymentConfig: ['projects', 'bookings', 'paymentConfig'] as const,

  taxonomy: ['taxonomy'] as const,
  categories: () => ['taxonomy', 'categories'] as const,
  propertyTypes: () => ['taxonomy', 'propertyTypes'] as const,
  subcategoriesByCategory: (categoryId: ObjectId) =>
    ['taxonomy', 'subcategories', categoryId] as const,

  sessions: ['profile', 'sessions'] as const,

  rewards: ['rewards'] as const,
  rewardsWallet: () => ['rewards', 'wallet'] as const,
  rewardsTransactions: () => ['rewards', 'transactions'] as const,
  rewardsReferralCode: () => ['rewards', 'referralCode'] as const,
  rewardsReferrals: () => ['rewards', 'referrals'] as const,
  rewardsStore: () => ['rewards', 'store'] as const,
  /** Public and slow-moving: the explainer numbers, not the user's balance. */
  rewardsPolicy: () => ['rewards', 'policy'] as const,

  /** Owner's own listing(s). Separate from `properties.saved`: this is what the
   *  signed-in owner is SELLING, not what they marked interest in. */
  myProperties: () => ['properties', 'mine'] as const,

  leads: ['leads'] as const,
  leadList: (params: Record<string, string | number | undefined>) =>
    ['leads', 'list', params] as const,
  leadAnalytics: (days: number) => ['leads', 'analytics', days] as const,

  /**
   * Deals: the lead seen from either side (`GET /deals`). Its own domain,
   * not under `leads`, because a buyer has deals and no leads, and because
   * a visit or a message changes a deal without changing the owner's CRM
   * list. Every deal mutation invalidates the whole domain: the list rows
   * carry `stage`, `nextVisit` and `unread`, all of which a write can move.
   */
  deals: ['deals'] as const,
  /** Infinite list. `page` is the page param and deliberately excluded. */
  dealList: (params: Record<string, string | number | undefined>) =>
    ['deals', 'list', params] as const,
  dealDetail: (leadId: ObjectId) => ['deals', 'detail', leadId] as const,

  reviews: ['reviews'] as const,
  reviewEligibility: (verificationId: ObjectId) =>
    ['reviews', 'eligibility', verificationId] as const,
  /** Public, per subject. Infinite; `page` excluded as above. */
  reviewsForUser: (userId: ObjectId) => ['reviews', 'user', userId] as const,

  blogs: ['blogs'] as const,
  /** Empty string is the unfiltered feed, so both share one prefix. */
  blogList: (category: string) => ['blogs', 'list', category] as const,
  blogPost: (slug: string) => ['blogs', 'post', slug] as const,
} as const;
