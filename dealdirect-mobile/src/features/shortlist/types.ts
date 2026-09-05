/**
 * The shortlist row, as every surface renders it.
 *
 * ONE shape for two sources. A row can come from the server (`GET /shortlist`,
 * carrying a note and an availability verdict) or from the device-local MMKV
 * store (a guest's list, and the offline cache behind the signed-in one). If
 * the two had separate types, every list, row and empty state in the feature
 * would branch twice, and the guest path would rot because nobody tests it.
 *
 * So the local source fills in the honest defaults: no entry id, no note,
 * available, no reason. `entryId` being absent is exactly the fact "this row
 * has not reached the server yet".
 */

import type { RailProperty } from '@/features/properties';
import type { ShortlistUnavailableReason } from '@/types/backend/shortlist';

export type { ShortlistUnavailableReason };

export interface ShortlistItem {
  /** Server entry id. Absent on a row that only exists on this device. */
  entryId?: string;
  property: RailProperty;
  /** Epoch ms. Newest first; there is no other ordering. */
  shortlistedAt: number;
  /** The user's private note. Never sent on a shared link. */
  note?: string;
  available: boolean;
  unavailableReason: ShortlistUnavailableReason | null;
}

/** Wording for a listing that is still on the list but no longer on the market. */
export const UNAVAILABLE_LABELS: Record<ShortlistUnavailableReason, string> = {
  sold: 'Sold',
  rented: 'Rented out',
  unavailable: 'No longer listed',
};
