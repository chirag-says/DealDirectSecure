import { useCallback, useSyncExternalStore } from 'react';

import { PREF_KEYS, prefsStorage } from '@/storage';
import type { PropertySummary } from './types';

/**
 * Listings the user has opened, newest first.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS STORES A SNAPSHOT INSTEAD OF A LIST OF IDS
 *
 * The tidy version keeps ids and refetches them for display. It is wrong here
 * for two reasons, and the second one is the important one.
 *
 * First, cost. Ten ids is ten `GET /properties/:id` calls to draw one row.
 *
 * Second, and decisively: `GET /properties/:id` INCREMENTS THE VIEW COUNTER on
 * every call (see the endpoint note in `api/endpoints/properties.ts`). Refetching
 * to render "Recently Viewed" would inflate the view count of everything the
 * user has ever opened, every time they scroll past this row on Home. The one
 * behavioural signal the backend actually collects would be corrupted by the
 * feature that displays it.
 *
 * So the card's fields are captured at view time and replayed from disk. The
 * row costs zero requests and zero view-count pollution.
 *
 * The trade is staleness: a price change or a delisting is not reflected until
 * the user opens that listing again. That is the correct trade for a history
 * row — it is a record of what you looked at, and the detail screen it opens
 * fetches live data anyway, which is where a stale price would actually matter.
 *
 * ---------------------------------------------------------------------------
 * Device preference, not account data, so it lives in `prefsStorage` and
 * survives logout alongside recent searches.
 */

const MAX_ENTRIES = 12;

/**
 * A trimmed `PropertySummary`.
 *
 * Only the fields the compact card draws are persisted. Storing the full
 * summary would put roughly twenty unused fields per entry into MMKV, and would
 * silently keep whatever the adapter shape happened to be on the day it was
 * written, which then has to be migrated.
 */
export interface ViewedProperty {
  id: string;
  title: string;
  priceRupees: number;
  intent: PropertySummary['intent'];
  coverImage?: string;
  locationLabel: string;
  bhk?: string;
  propertyTypeName?: string;
  /** Epoch ms, for ordering and for pruning. */
  viewedAt: number;
}

function read(): ViewedProperty[] {
  const raw = prefsStorage.getString(PREF_KEYS.recentlyViewed);
  if (!raw) return [];

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    // Validated per entry rather than trusted wholesale: this data can outlive
    // several versions of the app, and one malformed row must not blank the
    // whole row for everyone who upgrades.
    return parsed.filter(
      (item): item is ViewedProperty =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as ViewedProperty).id === 'string' &&
        typeof (item as ViewedProperty).viewedAt === 'number'
    );
  } catch {
    prefsStorage.remove(PREF_KEYS.recentlyViewed);
    return [];
  }
}

/**
 * Subscriber set for `useSyncExternalStore`.
 *
 * MMKV is synchronous and has no React binding, so a component that reads it
 * once never learns that the user opened a listing on another screen. Without
 * this, the "Recently Viewed" row would be correct only on a cold start and
 * would silently go stale for the whole session.
 */
const listeners = new Set<() => void>();

/**
 * Cached so `getSnapshot` returns a STABLE reference between writes.
 *
 * `useSyncExternalStore` compares snapshots with `Object.is`. Parsing JSON on
 * every call returns a new array each time, which reads as "changed" on every
 * render and loops infinitely. The cache is invalidated only by `record` and
 * `clear`, which are the only things that can change the stored value.
 */
let snapshot: ViewedProperty[] | null = null;

function getSnapshot(): ViewedProperty[] {
  if (snapshot === null) snapshot = read();
  return snapshot;
}

function emit(next: ViewedProperty[]): void {
  snapshot = next;
  prefsStorage.set(PREF_KEYS.recentlyViewed, JSON.stringify(next));
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Records a view. Call from the property detail screen, not from a card press.
 *
 * Detail-screen mount is the honest definition of "viewed": tapping a card can
 * be a mis-tap, and the back gesture that follows should not have written
 * history. It also matches where the backend increments its own counter, so the
 * two notions of a view agree.
 *
 * Re-viewing moves an entry to the front rather than duplicating it.
 */
export function recordView(property: PropertySummary): void {
  const entry: ViewedProperty = {
    id: property.id,
    title: property.title,
    priceRupees: property.priceRupees,
    intent: property.intent,
    coverImage: property.coverImage,
    locationLabel: property.locationLabel,
    bhk: property.bhk,
    propertyTypeName: property.propertyTypeName,
    viewedAt: Date.now(),
  };

  const rest = getSnapshot().filter((item) => item.id !== entry.id);
  emit([entry, ...rest].slice(0, MAX_ENTRIES));
}

export function clearRecentlyViewed(): void {
  emit([]);
}

/** Live-updating history. Re-renders when a listing is opened anywhere. */
export function useRecentlyViewed(): ViewedProperty[] {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/** Stable callback for the detail screen. */
export function useRecordView(): (property: PropertySummary) => void {
  return useCallback((property: PropertySummary) => recordView(property), []);
}
