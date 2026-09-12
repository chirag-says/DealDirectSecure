import type * as LocationModule from 'expo-location';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * The device's location, when the user has asked for it.
 *
 * ---------------------------------------------------------------------------
 * FOREGROUND, ONE-SHOT, ON DEMAND
 *
 * Every call here is triggered by a user action — tapping "near me", or opening
 * the city picker and choosing "use my location". There is no watcher, no
 * background permission, and nothing runs at launch. A property app has no
 * business tracking anyone; it needs one coordinate at the moment the user asks
 * "what is around me", and that is all this provides.
 *
 * ---------------------------------------------------------------------------
 * PERMISSION IS NOT REQUESTED AT LAUNCH
 *
 * The prompt fires the first time the user invokes a feature that needs it, not
 * on cold start, because a permission dialog with no context is the fastest way
 * to a permanent denial. `getCoordinates` requests only when called.
 *
 * The result type distinguishes the outcomes the UI must handle differently: a
 * granted coordinate, a denial the user can be nudged past, and an absent
 * module that the caller must simply hide the feature for.
 */

const Location = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-location') as typeof LocationModule,
  'expo-location',
  'Location features are unavailable in this host.'
);

export const locationAvailable = Location !== null;

export interface Coordinates {
  latitude: number;
  longitude: number;
}

export type LocationResult =
  | { status: 'ok'; coordinates: Coordinates }
  | { status: 'denied' }
  | { status: 'unavailable' }
  | { status: 'error' };

/**
 * One coordinate, requesting permission if needed.
 *
 * `Balanced` accuracy rather than `Highest`: a property search cares which
 * locality you are in, not which room, and the high-accuracy fix costs seconds
 * and battery for precision the feature throws away.
 */
export async function getCoordinates(): Promise<LocationResult> {
  if (!Location) return { status: 'unavailable' };

  try {
    const permission = await Location.requestForegroundPermissionsAsync();
    if (!permission.granted) return { status: 'denied' };

    const position = await Location.getCurrentPositionAsync({
      accuracy: Location.Accuracy.Balanced,
    });

    return {
      status: 'ok',
      coordinates: {
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
      },
    };
  } catch {
    return { status: 'error' };
  }
}

export type CityResult =
  | {
      status: 'ok';
      coordinates: Coordinates;
      /**
       * Place names the geocoder offered for the coordinate, most specific
       * first, empty if it offered none. Which of `city`, `subregion` and
       * `district` is populated varies by platform and by how dense the area
       * is, so all of them are handed over rather than one guessed at.
       */
      names: string[];
    }
  | { status: 'denied' }
  | { status: 'unavailable' }
  | { status: 'error' };

/**
 * Where the user is, as a coordinate plus whatever the device calls it.
 *
 * Uses expo-location's own reverse geocoder — the OS's, on Android — rather
 * than a network call to Nominatim. That keeps the "detect my city" path
 * off the network entirely, and off any third-party geocoding quota.
 *
 * The coordinate is the primary answer (2026-09-06). This used to return a
 * single name and fail when the geocoder returned none or returned a
 * district, which on Android is the usual case. Now a geocoder failure is
 * not a detection failure: the caller resolves the coordinate against the
 * app's own city table first (`nearestCity`) and uses the names only as a
 * fallback. See `features/home/detectCity.ts`.
 */
export async function getCurrentCity(): Promise<CityResult> {
  if (!Location) return { status: 'unavailable' };

  const located = await getCoordinates();
  if (located.status !== 'ok') {
    return located.status === 'denied' ? { status: 'denied' } : { status: 'error' };
  }

  let names: string[] = [];
  try {
    const [first] = await Location.reverseGeocodeAsync(located.coordinates);
    names = [first?.city, first?.subregion, first?.district, first?.region].filter(
      (name): name is string => typeof name === 'string' && name.trim().length > 0
    );
  } catch {
    // The coordinate alone is enough; see the doc comment.
  }

  return { status: 'ok', coordinates: located.coordinates, names };
}

/**
 * Whether permission is already granted, without prompting.
 *
 * Lets a screen show "near me" as active rather than as a request when the user
 * has already said yes, and avoids a redundant prompt.
 */
export async function hasLocationPermission(): Promise<boolean> {
  if (!Location) return false;
  try {
    const permission = await Location.getForegroundPermissionsAsync();
    return permission.granted;
  } catch {
    return false;
  }
}

/** Address components resolved from a coordinate, all possibly empty. */
export interface ResolvedPlace {
  city: string;
  locality: string;
  addressLine: string;
  state: string;
  pincode: string;
  landmark: string;
}

export type PlaceResult =
  | { status: 'ok'; place: ResolvedPlace }
  | { status: 'denied' }
  | { status: 'unavailable' }
  | { status: 'error' };

/**
 * Reverse-geocode a coordinate into address parts, for the listing form.
 *
 * `getCurrentCity` above answers "which of our cities am I in", which is a
 * different question with a different consumer — it matches against the app's
 * own city table and discards everything else. This one keeps the parts,
 * because the listing form has a field for each of them.
 *
 * The website does this with a direct Nominatim call carrying no API key, no
 * User-Agent and no rate-limit handling, which violates Nominatim's usage
 * policy and would be the first thing to break under real traffic. expo-
 * location's geocoder is the OS's, so this costs no quota, needs no key, works
 * offline on Android where the OS has cached it, and cannot be rate-limited out
 * from under the form.
 */
export async function describeCoordinates(
  latitude: number,
  longitude: number
): Promise<PlaceResult> {
  if (!Location) return { status: 'unavailable' };

  try {
    const [place] = await Location.reverseGeocodeAsync({ latitude, longitude });
    if (!place) return { status: 'error' };

    /*
      Each field falls through several of the geocoder's names, because which
      one is populated varies by country, by platform and by how dense the area
      is. `district` is the locality in most Indian results; `subregion` is the
      district in the administrative sense and is the better city fallback than
      `region`, which is the state.
    */
    return {
      status: 'ok',
      place: {
        city: place.city ?? place.subregion ?? '',
        locality: place.district ?? place.subregion ?? '',
        addressLine: [place.streetNumber, place.street ?? place.name]
          .filter(Boolean)
          .join(' ')
          .trim(),
        state: place.region ?? '',
        pincode: place.postalCode ?? '',
        // Only useful when it is NOT just a repeat of the street already in
        // `addressLine` — a landmark that duplicates the address is noise.
        landmark: place.name && place.name !== place.street ? place.name : '',
      },
    };
  } catch {
    return { status: 'error' };
  }
}

export type GeocodeResult =
  | { status: 'ok'; coordinates: Coordinates }
  | { status: 'unavailable' }
  | { status: 'notFound' }
  | { status: 'error' };

/**
 * Forward-geocode a written address into a coordinate.
 *
 * Lets the map follow what the owner typed, so the pin is roughly right before
 * they touch it. Same reasoning as `describeCoordinates` for using the OS
 * geocoder rather than the website's un-keyed Nominatim call.
 *
 * `notFound` is distinct from `error`: an address the geocoder cannot place is
 * a normal outcome for a half-typed locality, and must not be reported to the
 * owner as a failure.
 */
export async function geocodeAddress(query: string): Promise<GeocodeResult> {
  if (!Location) return { status: 'unavailable' };
  if (query.trim().length < 3) return { status: 'notFound' };

  try {
    const [match] = await Location.geocodeAsync(query.trim());
    if (!match) return { status: 'notFound' };
    return {
      status: 'ok',
      coordinates: { latitude: match.latitude, longitude: match.longitude },
    };
  } catch {
    return { status: 'error' };
  }
}
