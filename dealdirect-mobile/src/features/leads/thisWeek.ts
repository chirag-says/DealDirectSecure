/**
 * The owner's week, derived on the client from the lead list.
 *
 * `GET /leads/analytics` carries `newLeadsThisWeek` but nothing about who is
 * waiting, and the weekly digest email (Phase 2, `jobs/ownerWeeklyDigest.js`)
 * is what the "This week" card on the analytics screen previews. Both numbers
 * come from the rows the list already fetched, so the card costs no request.
 *
 * A lead is WAITING ON THE OWNER when the owner has not replied and the buyer
 * has been left for more than a day. "Replied" is `firstOwnerResponseAt` when
 * the backend sends the field (Phase 2 rows carry it, null until set), and
 * `isViewed` on rows from an older backend that never had it: opening the
 * lead was the only response the old model recorded. Closed leads, won or
 * lost, are not waiting on anyone.
 *
 * `useLeads` pages twenty at a time newest first, so the counts are exact
 * only when every lead is loaded. `lowerBound` says when they are not, and
 * the screen shows "20+" rather than "20".
 */

import type { Lead } from '@/types/backend/lead';

const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;

export interface WeekSummary {
  /** Leads created in the last seven days. */
  newLeads: number;
  /** Open leads older than a day that the owner has not answered. */
  waiting: number;
  /** True when more pages exist, so both counts may be undercounts. */
  lowerBound: boolean;
}

function hasOwnerReplied(lead: Lead): boolean {
  if ('firstOwnerResponseAt' in lead) return !!lead.firstOwnerResponseAt;
  return lead.isViewed !== false;
}

export function isWaitingOnOwner(lead: Lead, now: number): boolean {
  if (lead.status === 'converted' || lead.status === 'lost') return false;
  if (hasOwnerReplied(lead)) return false;
  const created = new Date(lead.createdAt).getTime();
  if (Number.isNaN(created)) return false;
  return now - created > DAY_MS;
}

export function summariseWeek(leads: Lead[], hasMore: boolean, now = Date.now()): WeekSummary {
  let newLeads = 0;
  let waiting = 0;

  for (const lead of leads) {
    const created = new Date(lead.createdAt).getTime();
    if (!Number.isNaN(created) && now - created <= WEEK_MS) newLeads += 1;
    if (isWaitingOnOwner(lead, now)) waiting += 1;
  }

  return { newLeads, waiting, lowerBound: hasMore };
}
