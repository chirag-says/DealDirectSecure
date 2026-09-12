import { getCurrentCity } from '@/native';

import { matchCityLoosely, nearestCity, type City } from './cities';

/**
 * Which of the app's cities the device is in.
 *
 * Two answers are tried, in order:
 *
 *   1. The coordinate against the city table's own centres and radii. This
 *      is deterministic, needs no network and cannot be misspelled, and it
 *      is what fixed detection on Android, where the reverse geocoder names
 *      the district ("Bengaluru Urban") rather than the city.
 *   2. Any name the geocoder offered, matched loosely, for a user outside
 *      every radius whose device still names a city the app knows.
 *
 * `outside` carries the most specific name the device gave, so the picker
 * can say "We are not in Coimbatore yet" rather than a bare failure.
 */
export type DetectCityResult =
  | { status: 'found'; city: City }
  | { status: 'outside'; placeName: string | null }
  | { status: 'denied' }
  | { status: 'unavailable' }
  | { status: 'error' };

export async function detectCity(): Promise<DetectCityResult> {
  const located = await getCurrentCity();
  if (located.status !== 'ok') return { status: located.status };

  const byDistance = nearestCity(located.coordinates);
  if (byDistance) return { status: 'found', city: byDistance };

  for (const name of located.names) {
    const byName = matchCityLoosely(name);
    if (byName) return { status: 'found', city: byName };
  }

  return { status: 'outside', placeName: located.names[0] ?? null };
}
