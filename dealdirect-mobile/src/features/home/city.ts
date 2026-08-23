import { useSyncExternalStore } from 'react';

import { PREF_KEYS, prefsStorage } from '@/storage';
import { CITIES, type City } from './cities';

/**
 * The city the user is shopping in.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS AT ALL
 *
 * Every large Indian portal opens by asking which city you are in and then
 * scopes the whole session to it, because "properties" without a city is not a
 * question anyone has. DealDirect's search has always taken a city filter; what
 * it never had was somewhere to REMEMBER the answer, so a user picked Bangalore
 * on the results screen and was back to the whole country on their next visit.
 *
 * Device preference, not account data, so it lives in `prefsStorage` alongside
 * the theme and recent searches and survives logout. There is no server field
 * for it and this does not invent one.
 *
 * Null is a real value and the default: "everywhere". A first-run user is not
 * forced through a city picker before they can see anything, which is the one
 * thing those portals get wrong.
 */

function read(): City | null {
  const id = prefsStorage.getString(PREF_KEYS.selectedCity);
  if (!id) return null;
  // Resolved against the table rather than trusted: a stored id from an older
  // build whose city has since been removed must degrade to "everywhere", not
  // to a filter the user cannot see or clear.
  return CITIES.find((city) => city.id === id) ?? null;
}

/** See the note on this pattern in `properties/recentlyViewed.ts`. */
const listeners = new Set<() => void>();
let snapshot: City | null | undefined;

function getSnapshot(): City | null {
  if (snapshot === undefined) snapshot = read();
  return snapshot;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function setSelectedCity(city: City | null): void {
  snapshot = city;
  if (city) prefsStorage.set(PREF_KEYS.selectedCity, city.id);
  else prefsStorage.remove(PREF_KEYS.selectedCity);
  listeners.forEach((listener) => listener());
}

export function useSelectedCity(): City | null {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}
