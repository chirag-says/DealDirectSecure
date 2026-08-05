import { Platform } from 'react-native';

import { APP_VERSION } from '@/config/env';

/**
 * The session User-Agent constant.
 *
 * THIS IS LOAD-BEARING. Read before changing anything in this file.
 *
 * The backend fingerprints each session from the User-Agent
 * (`UserSession.validateFingerprintLenient`) and REVOKES the session when the
 * derived OS family or device type changes. An IP change is tolerated; a
 * User-Agent change is not.
 *
 * Two consequences:
 *
 *  1. Every authenticated request must send exactly this string. A single call
 *     from a different HTTP client, including file downloads, flips the
 *     fingerprint and silently logs the user out.
 *  2. The app VERSION must never appear here. Interpolating it would change the
 *     fingerprint on every release and log out the entire user base on upgrade
 *     day. Version travels in `X-App-Version`, which the fingerprint ignores.
 *
 * The strings below are chosen to parse deterministically through the backend's
 * `extractOsFamily` and `extractDeviceType`:
 *
 *   contains "Android"            → os Android
 *   contains "iPhone" or "iPad"   → os iOS
 *   contains "Mobile"             → device Mobile
 *   contains "Tablet" or "iPad"   → device Tablet
 *
 * These do NOT apply to OSM tile or Nominatim requests, which carry no cookie
 * and reach no DealDirect host. Those send their own identifying agent.
 */

function buildSessionUserAgent(): string {
  if (Platform.OS === 'android') {
    return 'DealDirect (Android; Mobile)';
  }

  if (Platform.OS === 'ios') {
    // Platform.isPad is iOS-only and stable for the life of the install, so the
    // derived device type cannot change between requests on one device.
    return Platform.isPad ? 'DealDirect (iPad; Tablet)' : 'DealDirect (iPhone; Mobile)';
  }

  // Web and anything else. Not a shipping target, but it must still be constant.
  return 'DealDirect (Mobile)';
}

export const SESSION_USER_AGENT = buildSessionUserAgent();

/**
 * Headers every DealDirect request must carry.
 *
 * Use this for ANY authenticated call made outside the shared axios instances,
 * such as an `expo-file-system` download of an agreement PDF or the leads
 * export. Omitting it there is what silently ends the session.
 */
export function sessionHeaders(): Record<string, string> {
  return {
    'User-Agent': SESSION_USER_AGENT,
    'X-App-Version': APP_VERSION,
  };
}
