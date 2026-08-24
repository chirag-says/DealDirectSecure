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
