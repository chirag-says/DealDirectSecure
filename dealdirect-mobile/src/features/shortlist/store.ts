import { useSyncExternalStore } from 'react';

import type { RailProperty } from '@/features/properties';
import { PREF_KEYS, prefsStorage } from '@/storage';
import type { ShortlistItem, ShortlistUnavailableReason } from './types';

/**
 * The shortlist: listings the user is CONSIDERING.
 *
 * ---------------------------------------------------------------------------
 * THIS IS NOT THE INTERESTED LIST, AND THE DIFFERENCE IS STILL THE POINT
 *
 * `POST /properties/interested/:id` creates a Lead, emails the owner, sends
 * them a WhatsApp message carrying the user's name, email and phone, awards
 * points, and counts against a hard cap of five. That is an announcement, and
 * the app is right to put a consequence sheet in front of it.
 *
 * A shortlist entry does none of that. It notifies nobody, creates no Lead,
 * awards no points, and is capped by nothing. Phase 1 (F7) gave it a server of
 * its own, `/api/shortlist`, so it now follows the user to a second phone, but
 * the separation from the enquiry is unchanged and is enforced on both sides.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS NOW: THE SYNCHRONOUS READ MODEL
 *
 * Before Phase 1 this WAS the shortlist. It is now two narrower things:
 *
 *   1. The guest list. A signed-out user still saves, still sees their list,
 *      and their saves are handed to the server once at sign-in (`merge.ts`).
 *   2. The offline cache behind the signed-in list. Every successful
 *      `GET /shortlist` writes its rows here, so a cold start with no
 *      connectivity draws the real list rather than an empty state.
 *
 * It stays synchronous and store-shaped on purpose. Home reads
 * `useShortlist().length` and must not cause a request to do it (HANDOFF 5.2:
 * no eager queries on Home), and a save button has to flip under the thumb
 * with no await. The network half lives in `hooks.ts`; this file still imports
 * no API client, and that is still checkable by reading its imports.
 *
 * ---------------------------------------------------------------------------
 * WHY IT STORES SNAPSHOTS RATHER THAN IDS
 *
 * `GET /properties/:id` INCREMENTS THE VIEW COUNTER. A cache that refetched
 * its rows to draw them would inflate the view count of everything the user is
 * considering, every time they opened the tab, corrupting the one demand
 * signal the backend collects using the feature that displays it. So the card
 * fields are captured at save time, or copied from the list response, and
 * replayed from disk.
 *
 * `RailProperty` is the stored shape because it is exactly the structural
 * subset a card needs. See its own note.
 */

/** The persisted row. Superset of the pre-Phase-1 shape, which still parses. */
export interface StoredShortlistEntry {
  property: RailProperty;
  /** Epoch ms. */
  shortlistedAt: number;
  entryId?: string;
  note?: string;
  available?: boolean;
  unavailableReason?: ShortlistUnavailableReason | null;
}

/** Kept under its old name for the import paths that still say it. */
export type ShortlistedProperty = StoredShortlistEntry;

/**
 * A ceiling, not a cap the user should ever meet.
 *
 * The shortlist is advertised as unlimited and for every real user it is. Two
 * hundred matches the server's merge cap, so the local list can never exceed
 * what a single handover can carry.
 */
const MAX_ENTRIES = 200;

function read(): StoredShortlistEntry[] {
  const raw = prefsStorage.getString(PREF_KEYS.shortlist);
  if (!raw) return [];

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    // Validated per entry rather than trusted wholesale: this data outlives app
    // versions, and one malformed row must not blank the list for everyone who
    // upgrades.
    return parsed.filter(
      (item): item is StoredShortlistEntry =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as StoredShortlistEntry).shortlistedAt === 'number' &&
        typeof (item as StoredShortlistEntry).property?.id === 'string'
    );
  } catch {
    prefsStorage.remove(PREF_KEYS.shortlist);
    return [];
  }
}

/** See the note on this pattern in `properties/recentlyViewed.ts`. */
const listeners = new Set<() => void>();
let snapshot: StoredShortlistEntry[] | null = null;

function getSnapshot(): StoredShortlistEntry[] {
  if (snapshot === null) snapshot = read();
  return snapshot;
}

function emit(next: StoredShortlistEntry[]): void {
  snapshot = next;
  prefsStorage.set(PREF_KEYS.shortlist, JSON.stringify(next));
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Membership on this device. Synchronous, and correct on its own for a guest. */
export function isLocallyShortlisted(id: string): boolean {
  return getSnapshot().some((entry) => entry.property.id === id);
}

export function localShortlistIds(): string[] {
  return getSnapshot().map((entry) => entry.property.id);
}

/**
 * Adds or removes locally, and returns the state it landed in.
 *
 * Synchronous, so the caller can paint the result immediately. When a session
 * exists, `useToggleShortlist` calls this FIRST and then reconciles with the
 * server, restoring the row if the request fails, which is what makes the
 * optimistic update and the guest path the same code.
 *
 * Re-adding an entry that is already present moves it to the front rather than
 * duplicating it, matching how `recentlyViewed` treats a repeat view.
 */
export function toggleLocalShortlist(property: RailProperty): boolean {
  const current = getSnapshot();
  const existing = current.some((entry) => entry.property.id === property.id);

  if (existing) {
    emit(current.filter((entry) => entry.property.id !== property.id));
    return false;
  }

  const entry: StoredShortlistEntry = { property, shortlistedAt: Date.now() };
  emit([entry, ...current.filter((item) => item.property.id !== property.id)].slice(0, MAX_ENTRIES));
  return true;
}

/** Puts a row back after a failed server write. Preserves the original time. */
export function restoreLocalShortlist(entry: StoredShortlistEntry): void {
  const current = getSnapshot().filter((item) => item.property.id !== entry.property.id);
  emit([entry, ...current].slice(0, MAX_ENTRIES));
}

export function findLocalShortlistEntry(id: string): StoredShortlistEntry | undefined {
  return getSnapshot().find((entry) => entry.property.id === id);
}

/** Removal from the list itself, where there is no property object to hand. */
export function removeLocalShortlist(id: string): void {
  emit(getSnapshot().filter((entry) => entry.property.id !== id));
}

/**
 * Replaces the cache wholesale with what the server just said.
 *
 * Called after a successful `GET /shortlist`. Replace, not merge: the server
 * is the truth for a signed-in user, and merging would resurrect a row they
 * deleted on another device, which is the exact bug a sync feature exists to
 * avoid.
 */
export function setLocalShortlist(entries: StoredShortlistEntry[]): void {
  emit(entries.slice(0, MAX_ENTRIES));
}

/** After a successful handover to the server. See `merge.ts`. */
export function clearLocalShortlist(): void {
  emit([]);
}

/** Writes one row's note into the cache so the offline copy stays truthful. */
export function setLocalShortlistNote(id: string, note: string): void {
  emit(
    getSnapshot().map((entry) =>
      entry.property.id === id ? { ...entry, note: note || undefined } : entry
    )
  );
}

export function useLocalShortlist(): StoredShortlistEntry[] {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * The stored row as the UI's row type.
 *
 * A local row is always "available": nothing on this device knows otherwise,
 * and guessing an unavailability the server has not reported would be worse
 * than saying nothing.
 */
export function localEntryToItem(entry: StoredShortlistEntry): ShortlistItem {
  return {
    entryId: entry.entryId,
    property: entry.property,
    shortlistedAt: entry.shortlistedAt,
    note: entry.note,
    available: entry.available ?? true,
    unavailableReason: entry.unavailableReason ?? null,
  };
}
