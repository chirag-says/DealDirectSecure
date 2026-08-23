import { useSyncExternalStore } from 'react';

import type { RailProperty } from '@/features/properties';
import { PREF_KEYS, prefsStorage } from '@/storage';

/**
 * The shortlist: listings the user is CONSIDERING.
 *
 * ---------------------------------------------------------------------------
 * THIS IS NOT THE INTERESTED LIST, AND THE DIFFERENCE IS THE POINT
 *
 * DealDirect has exactly one server-side notion of "saved", and it is not a
 * bookmark. `POST /properties/interested/:id` creates a Lead, emails the
 * owner, sends them a WhatsApp message carrying the user's name, email and
 * phone, awards points, and counts against a hard cap of five. That is an
 * announcement, and the app is right to put a consequence sheet in front of it.
 *
 * What did not exist anywhere in the product is the other thing — the twenty
 * flats you are turning over while you decide which five are worth contacting
 * anyone about. Every portal has it, and users expect it to be free, private,
 * unlimited and instant, because that is what a bookmark means.
 *
 * So this list:
 *
 *   - creates no Lead,
 *   - notifies no owner,
 *   - sends no WhatsApp and no email,
 *   - awards no points,
 *   - never touches `/properties/interested/*` or any other endpoint,
 *   - is capped by nothing.
 *
 * It cannot do any of those things by construction rather than by discipline:
 * this module imports no API client. There is no code path from a shortlist tap
 * to a request.
 *
 * ---------------------------------------------------------------------------
 * DEVICE-LOCAL, AND SAID OUT LOUD
 *
 * There is no shortlist on the server. Adding one is a backend change that has
 * not been approved, so the list lives in MMKV on this device: it does not
 * follow the user to another phone, and reinstalling loses it.
 *
 * That is a real limitation and the UI states it rather than hiding it — see
 * the footnote on the Activity segment. The alternative was to build the
 * feature on top of the interested endpoint, which would have meant every
 * bookmark emailing an owner. Local and honest beats synced and wrong.
 *
 * When a server shortlist is approved, this store becomes the offline cache in
 * front of it and the migration is one upload of whatever is here.
 *
 * ---------------------------------------------------------------------------
 * WHY IT STORES SNAPSHOTS RATHER THAN IDS
 *
 * Same reason as `properties/recentlyViewed.ts`, and the second half is the
 * one that decides it: `GET /properties/:id` INCREMENTS THE VIEW COUNTER. A
 * shortlist that refetched its rows to draw them would inflate the view count
 * of everything the user is considering, every time they opened the tab —
 * corrupting the one demand signal the backend collects, using the feature that
 * displays it.
 *
 * So the card's fields are captured at shortlist time and replayed from disk.
 * The list costs zero requests. The trade is staleness: a price change or a
 * delisting is not reflected until the listing is opened again, and the detail
 * screen it opens fetches live data anyway, which is where a stale price would
 * actually matter.
 *
 * `RailProperty` is the stored shape rather than the full `PropertySummary`
 * because it is exactly the structural subset a card needs — see its own note.
 * Storing the full summary would persist twenty unused fields per entry and
 * freeze whatever the adapter shape happened to be on the day it was written.
 */

export interface ShortlistedProperty {
  property: RailProperty;
  /** Epoch ms. Newest first; there is no other ordering. */
  shortlistedAt: number;
}

/**
 * A ceiling, not a cap the user should ever meet.
 *
 * The shortlist is advertised as unlimited and for every real user it is: two
 * hundred is far past the point where a human is still comparing. It exists so
 * a runaway loop or a stuck finger cannot grow an MMKV value without bound,
 * and it trims the oldest rather than refusing the newest, so the behaviour at
 * the edge is invisible rather than a wall.
 */
const MAX_ENTRIES = 200;

function read(): ShortlistedProperty[] {
  const raw = prefsStorage.getString(PREF_KEYS.shortlist);
  if (!raw) return [];

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    // Validated per entry rather than trusted wholesale: this data outlives app
    // versions, and one malformed row must not blank the list for everyone who
    // upgrades.
    return parsed.filter(
      (item): item is ShortlistedProperty =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as ShortlistedProperty).shortlistedAt === 'number' &&
        typeof (item as ShortlistedProperty).property?.id === 'string'
    );
  } catch {
    prefsStorage.remove(PREF_KEYS.shortlist);
    return [];
  }
}

/** See the note on this pattern in `properties/recentlyViewed.ts`. */
const listeners = new Set<() => void>();
let snapshot: ShortlistedProperty[] | null = null;

function getSnapshot(): ShortlistedProperty[] {
  if (snapshot === null) snapshot = read();
  return snapshot;
}

function emit(next: ShortlistedProperty[]): void {
  snapshot = next;
  prefsStorage.set(PREF_KEYS.shortlist, JSON.stringify(next));
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function isShortlisted(id: string): boolean {
  return getSnapshot().some((entry) => entry.property.id === id);
}

/**
 * Adds or removes, and returns the state it landed in.
 *
 * Synchronous, so the caller can paint the result immediately — this is what
 * "optimistic" means for a store with no server behind it: there is no request
 * to be optimistic ABOUT, and no rollback path, because the write cannot fail
 * in a way the user needs to hear about.
 *
 * Re-adding an entry that is already present moves it to the front rather than
 * duplicating it, matching how `recentlyViewed` treats a repeat view.
 */
export function toggleShortlist(property: RailProperty): boolean {
  const current = getSnapshot();
  const existing = current.some((entry) => entry.property.id === property.id);

  if (existing) {
    emit(current.filter((entry) => entry.property.id !== property.id));
    return false;
  }

  const entry: ShortlistedProperty = { property, shortlistedAt: Date.now() };
  emit([entry, ...current.filter((item) => item.property.id !== property.id)].slice(0, MAX_ENTRIES));
  return true;
}

/** Removal from the list itself, where there is no property object to hand. */
export function removeFromShortlist(id: string): void {
  emit(getSnapshot().filter((entry) => entry.property.id !== id));
}

export function useShortlist(): ShortlistedProperty[] {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * Membership for one listing.
 *
 * Subscribes to the whole store and narrows, rather than keeping a per-id
 * subscription. The list is small and the derived boolean is stable, so a
 * component re-renders only when its own membership actually flips.
 */
export function useIsShortlisted(id: string | undefined): boolean {
  const items = useShortlist();
  if (!id) return false;
  return items.some((entry) => entry.property.id === id);
}
