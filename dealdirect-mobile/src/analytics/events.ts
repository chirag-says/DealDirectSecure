/**
 * The usage-event vocabulary, mirrored from the backend's whitelist.
 *
 * `POST /events` drops any name outside this set and any prop outside each
 * name's allowed keys, silently. That is the right server behaviour (a bad
 * client must not be able to fail a batch for everyone), but it means a typo
 * here would cost an event without a trace. So the map is the type: a call
 * site naming an event that does not exist, or passing a prop the server would
 * drop, is a compile error rather than a missing row in a dashboard.
 *
 * This file is pure TypeScript with no React Native import, so the queue tests
 * can run under `node --test`.
 */

export interface UsageEvents {
  session_start: { platform: 'android' | 'ios' };
  search: { city?: string; listingType?: string; results: number };
  property_view: { propertyId: string; source: string };
  shortlist_add: { propertyId: string };
  saved_search_create: { city?: string };
  contact_owner: { propertyId: string };
  deal_open: { leadId: string; stage?: string };
  visit_proposed: { leadId: string };
  visit_confirmed: { leadId: string };
  visit_done: { leadId: string; feedback?: string };
  message_sent: { leadId: string };
  agreement_generated: { leadId: string };
  reward_claim: { verificationId: string };
  push_opened: { kind: string };
  notification_opened: { kind: string };
  review_submitted: { verificationId: string };
  /** Phase 1 (F7). Fired when a share link is CREATED, not when it is opened. */
  shortlist_share: { count: number };
  /** Phase 4 (F18). One per locality screen open, deduped per slug per mount. */
  locality_view: { slug: string };
  /** Phase 1/4 (F19). The listing form actually showed a comparison line. */
  price_guidance_shown: { city: string };
}

export type UsageEventName = keyof UsageEvents;

/**
 * The runtime half of the whitelist. The queue rehydrates from disk, and a row
 * written by an older build under a name this build no longer sends is dropped
 * here rather than shipped for the server to drop.
 */
export const USAGE_EVENT_NAMES: ReadonlySet<string> = new Set<UsageEventName>([
  'session_start',
  'search',
  'property_view',
  'shortlist_add',
  'saved_search_create',
  'contact_owner',
  'deal_open',
  'visit_proposed',
  'visit_confirmed',
  'visit_done',
  'message_sent',
  'agreement_generated',
  'reward_claim',
  'push_opened',
  'notification_opened',
  'review_submitted',
  'shortlist_share',
  'locality_view',
  'price_guidance_shown',
]);

export function isUsageEventName(name: string): name is UsageEventName {
  return USAGE_EVENT_NAMES.has(name);
}
