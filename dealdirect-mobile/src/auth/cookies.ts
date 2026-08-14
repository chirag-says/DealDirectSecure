import { API_URL } from '@/config/env';
import { optionalNativeModule } from '@/config/optionalNative';
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
 *
 * ---------------------------------------------------------------------------
 * EXPO GO FALLBACK
 *
 * Expo Go does not bundle `@react-native-cookies/cookies`, so the jar cannot
 * be read or written there and the mirror described above is unavailable.
 *
 * What this deliberately does NOT do is replace it. The obvious substitute —
 * persist the token and attach it as an explicit `Cookie:` header on every
 * request — means hand-rolling session transport to save one login on a
 * preview host. That is the wrong trade: the failure mode of a hand-rolled
 * credential path is sending a live session token somewhere it does not
 * belong, which is not a class of bug worth risking for a convenience.
 *
 * So the fallback does strictly LESS, and nothing surprising:
 *
 *   capture  → null.  The platform jar still holds the cookie for this run, so
 *                     the user is genuinely logged in; there is just no mirror.
 *   restore  → false. Nothing to re-inject.
 *   clear    → still clears secure storage, which is the part that matters.
 *
 * `AuthProvider.establishSession` already handles a null capture as "degraded,
 * not broken" and proves the login with a real `/users/me` call instead, so
 * sign-in works normally in Expo Go. The one visible consequence is that a
 * cold start asks for the password again.
 */

const SESSION_COOKIE_NAME = 'user_session';

/** The two methods used here, so the fallback can satisfy the same shape. */
interface CookieJar {
  get(url: string): Promise<Record<string, { value?: string } | undefined> | undefined>;
  set(url: string, cookie: Record<string, unknown>): Promise<unknown>;
  clearAll(): Promise<unknown>;
}

const cookieJar = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => (require('@react-native-cookies/cookies') as { default: CookieJar }).default,
  '@react-native-cookies/cookies',
  'Sign-in works for this run, but a cold start will require logging in again.'
);

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
  if (!cookieJar) return null;

  try {
    const cookies = await cookieJar.get(apiOrigin());
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
  if (!cookieJar) return false;

  const stored = await sessionCookieStorage.get();
  if (!stored) return false;

  const origin = apiOrigin();

  try {
    await cookieJar.set(origin, {
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
  // Runs first and unconditionally: the mirror is the copy that survives a
  // cold start, so it must be gone even if the native jar is unavailable or
  // its clear throws.
  await sessionCookieStorage.clear();

  if (!cookieJar) return;

  try {
    await cookieJar.clearAll();
  } catch (error) {
    console.warn('[cookies] clear failed', error);
  }
}

/** Whether a session cookie is persisted. Does not prove it is still valid. */
export async function hasStoredSession(): Promise<boolean> {
  return (await sessionCookieStorage.get()) !== null;
}
