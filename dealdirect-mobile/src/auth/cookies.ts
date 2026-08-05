import CookieManager from '@react-native-cookies/cookies';

import { API_URL } from '@/config/env';
import { sessionCookieStorage } from '@/storage';

/**
 * Native cookie jar bridge.
 *
 * React Native routes HTTP through the platform networking stacks, which keep
 * their own cookie jars (NSHTTPCookieStorage on iOS, CookieManager on Android).
 * Within a running session that works on its own. Across a COLD START it is not
 * dependable: Android's jar is not guaranteed to survive process death and iOS
 * discards it on reinstall.
 *
 * Relying on the implicit behaviour produces intermittent "logged out for no
 * reason" reports, which are miserable to reproduce and worse to diagnose. So
 * the cookie is mirrored explicitly into the Keychain / Keystore after login
 * and re-injected on launch.
 *
 * `HttpOnly` is a browser-DOM restriction. It stops JavaScript in a web page
 * from reading the cookie; it does not stop native app code, and both platform
 * cookie managers expose the value to us. Nothing is being circumvented here:
 * the app is the legitimate holder of its own session.
 */

const SESSION_COOKIE_NAME = 'user_session';

/** Cookie scope is the API ORIGIN, not the full base URL with its /api path. */
function apiOrigin(): string {
  try {
    const url = new URL(API_URL);
    return `${url.protocol}//${url.host}`;
  } catch {
    return API_URL;
  }
}

/**
 * Reads the session cookie out of the native jar and mirrors it to secure
 * storage. Call after any response that may have set it.
 *
 * Returns the value when one was found, so callers can tell whether a login
 * actually established a session rather than assuming a 200 did.
 */
export async function captureSessionCookie(): Promise<string | null> {
  try {
    const cookies = await CookieManager.get(apiOrigin());
    const value = cookies?.[SESSION_COOKIE_NAME]?.value;

    if (!value) return null;

    await sessionCookieStorage.set(value);
    return value;
  } catch (error) {
    console.warn('[cookies] capture failed', error);
    return null;
  }
}

/**
 * Re-injects the persisted cookie into the native jar.
 *
 * Run before the first authenticated request of a cold start. Returns false
 * when there is nothing stored, which means the user is a guest and no session
 * probe is needed.
 *
 * The attributes mirror what the backend sets (`middleware/authUser.js`):
 * HttpOnly, path `/`, and Secure whenever the API is HTTPS. `domain` is
 * deliberately left unset so the cookie binds to the exact API host; the
 * backend's `COOKIE_DOMAIN=.dealdirect.in` widens it server-side, but the app
 * only ever talks to one host and a narrower binding is safer.
 */
export async function restoreSessionCookie(): Promise<boolean> {
  const stored = await sessionCookieStorage.get();
  if (!stored) return false;

  const origin = apiOrigin();

  try {
    await CookieManager.set(origin, {
      name: SESSION_COOKIE_NAME,
      value: stored,
      path: '/',
      httpOnly: true,
      secure: origin.startsWith('https'),
    });
    return true;
  } catch (error) {
    console.warn('[cookies] restore failed', error);
    return false;
  }
}

/** Clears the session from both the native jar and secure storage. */
export async function clearSessionCookie(): Promise<void> {
  await sessionCookieStorage.clear();

  try {
    await CookieManager.clearAll();
  } catch (error) {
    console.warn('[cookies] clear failed', error);
  }
}

/** Whether a session cookie is persisted. Does not prove it is still valid. */
export async function hasStoredSession(): Promise<boolean> {
  return (await sessionCookieStorage.get()) !== null;
}
