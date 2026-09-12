/**
 * Google sign-in, reduced to one call that returns an ID token.
 *
 * Everything the native SDK gives back other than `idToken` is deliberately
 * discarded. The email, name and photo in that payload come from the CLIENT and
 * are worth nothing to us: the backend reads all three out of the signed token
 * after verifying it against Google's public keys, and trusting the client copy
 * would be trusting an attacker to describe themselves.
 *
 * ---------------------------------------------------------------------------
 * CONFIGURATION
 *
 * `webClientId` is required on Android and is NOT a mistake — it is what makes
 * the Android SDK mint a token audienced to our backend rather than to the app.
 * Without it `idToken` comes back null and the failure looks like a backend
 * problem.
 *
 * Android also needs the signing-certificate SHA-1 registered against the
 * Android OAuth client, once per variant (debug, upload, Play App Signing).
 * Miss the Play App Signing one and sign-in works everywhere except the build
 * users actually install, which is a miserable thing to diagnose after release.
 *
 * ---------------------------------------------------------------------------
 * THIS IS A NATIVE MODULE
 *
 * It does not exist in Expo Go. It needs a development build or a release
 * build, and adding it changes the fingerprint — so the first build carrying
 * this cannot be delivered as an OTA update.
 */

import { TurboModuleRegistry, type TurboModule } from 'react-native';

import { GOOGLE_IOS_CLIENT_ID, GOOGLE_WEB_CLIENT_ID } from '@/config/env';

/**
 * The SDK, loaded lazily and allowed to be absent.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT A STATIC IMPORT
 *
 * `@react-native-google-signin/google-signin` is a NATIVE module. Expo Go ships
 * a fixed set of native modules and this is not among them, so importing it
 * there throws at module-evaluation time. `AuthProvider` imports this file to
 * get `forgetGoogleAccount`, and AuthProvider is mounted at the root — so a
 * static import crashes the ENTIRE APP on launch in Expo Go, before any screen
 * renders. Not "Google sign-in is unavailable": a white screen.
 *
 * A try/catch around the require() is NOT enough on its own. Metro reports a
 * module-evaluation failure to LogBox (the red error overlay) before the throw
 * ever reaches the catch, so the app survives but the user still sees an
 * error on the login screen. The package must not be EVALUATED at all unless
 * its native half is present — and that is checkable up front, cheaply and
 * without loading anything, through `TurboModuleRegistry.get`, which returns
 * null where `getEnforcing` throws. `RNGoogleSignin` is the name the package
 * registers itself under (it is the name in the error this replaced).
 *
 * The result: a build without the native side degrades to "no Google button"
 * and everything else in the app keeps working, with nothing in the log. That
 * is what makes the rest of this release testable in Expo Go, or in a dev
 * client built before this module was added, while Google itself needs a
 * fresh native build.
 */
const NATIVE_MODULE_NAME = 'RNGoogleSignin';

/** GoogleSignInStatusCodes.DEVELOPER_ERROR, as the SDK stringifies it. */
const DEVELOPER_ERROR_STATUS = '10';

function nativeModulePresent(): boolean {
  try {
    return TurboModuleRegistry.get<TurboModule>(NATIVE_MODULE_NAME) != null;
  } catch {
    return false;
  }
}
type GoogleSdk = typeof import('@react-native-google-signin/google-signin');

let sdk: GoogleSdk | null | undefined;

function loadSdk(): GoogleSdk | null {
  if (sdk !== undefined) return sdk;
  if (!nativeModulePresent()) {
    sdk = null;
    return null;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    sdk = require('@react-native-google-signin/google-signin') as GoogleSdk;
  } catch {
    sdk = null;
  }
  return sdk;
}

/** True only in a build whose native side actually carries the SDK. */
export function isGoogleSignInAvailable(): boolean {
  return loadSdk() !== null;
}

/** Shown when the build has no native Google SDK — Expo Go, chiefly. */
const EXPO_GO_MESSAGE =
  'Google sign-in needs a development build. It cannot run in Expo Go. Use email and password here.';

/** The user backed out of the Google sheet. Not an error worth showing. */
export class GoogleSignInCancelled extends Error {
  constructor() {
    super('Google sign-in was cancelled');
    this.name = 'GoogleSignInCancelled';
  }
}

/** Google sign-in cannot run on this device or in this build. */
export class GoogleSignInUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GoogleSignInUnavailable';
  }
}

/**
 * True when the build carries the client IDs needed to talk to Google.
 *
 * Screens use this to decide whether to render the button at all. A button that
 * always fails is worse than no button: it reads as a broken app rather than as
 * a feature that is not switched on.
 */
export function isGoogleSignInConfigured(): boolean {
  // BOTH conditions. A client ID with no native SDK (Expo Go) would render a
  // button that crashes on tap, which is worse than no button.
  return GOOGLE_WEB_CLIENT_ID.length > 0 && isGoogleSignInAvailable();
}

let configured = false;

function ensureConfigured(): void {
  if (configured) return;

  const google = loadSdk();
  if (!google) throw new GoogleSignInUnavailable(EXPO_GO_MESSAGE);

  google.GoogleSignin.configure({
    webClientId: GOOGLE_WEB_CLIENT_ID,
    ...(GOOGLE_IOS_CLIENT_ID ? { iosClientId: GOOGLE_IOS_CLIENT_ID } : {}),
    // No server auth code and no offline access: the backend verifies an ID
    // token and issues its own session cookie. It never calls Google on the
    // user's behalf, so there is nothing to refresh and no refresh token worth
    // the trouble of holding.
    offlineAccess: false,
    scopes: ['profile', 'email'],
  });

  configured = true;
}

/**
 * Presents the native account picker and returns Google's signed ID token.
 *
 * Throws `GoogleSignInCancelled` when the user dismisses the sheet, and
 * `GoogleSignInUnavailable` when the device or build cannot do this at all.
 * Both are expected outcomes with their own handling, not faults.
 */
export async function signInWithGoogle(): Promise<string> {
  const google = loadSdk();
  if (!google) throw new GoogleSignInUnavailable(EXPO_GO_MESSAGE);
  if (!GOOGLE_WEB_CLIENT_ID) {
    throw new GoogleSignInUnavailable('Google sign-in is not configured in this build.');
  }

  ensureConfigured();

  try {
    // Android only, and a no-op elsewhere. A device without current Play
    // Services shows the system update prompt rather than failing silently.
    await google.GoogleSignin.hasPlayServices({ showPlayServicesUpdateDialog: true });

    // Signing out first makes the account picker appear every time. Without
    // it the SDK silently reuses the last account, so a user with two Google
    // accounts on the phone cannot switch, and someone handed a friend's
    // device signs into the friend's account without being asked.
    await google.GoogleSignin.signOut();

    const response = await google.GoogleSignin.signIn();

    if (!google.isSuccessResponse(response)) {
      throw new GoogleSignInCancelled();
    }

    const idToken = response.data.idToken;
    if (!idToken) {
      // Almost always a missing or mismatched webClientId: the SDK succeeds and
      // returns a user with no token. Naming it here saves an hour later.
      throw new GoogleSignInUnavailable(
        'Google did not return an identity token. Check that the web client ID and the signing certificate fingerprint are registered.'
      );
    }

    return idToken;
  } catch (error) {
    if (error instanceof GoogleSignInCancelled || error instanceof GoogleSignInUnavailable) {
      throw error;
    }

    if (google.isErrorWithCode(error)) {
      switch (error.code) {
        case google.statusCodes.SIGN_IN_CANCELLED:
          throw new GoogleSignInCancelled();
        case google.statusCodes.IN_PROGRESS:
          // A second tap while the first sheet is still opening.
          throw new GoogleSignInCancelled();
        case google.statusCodes.PLAY_SERVICES_NOT_AVAILABLE:
          throw new GoogleSignInUnavailable(
            'Google Play Services is not available on this device. Please sign in with email instead.'
          );
        // Play Services status 10. Not a network problem and not the user's
        // doing: Google has no Android OAuth client matching this app's package
        // name and signing-certificate SHA-1. Surfaced as "Could not reach
        // Google" it cost a full debugging loop on 2026-09-12; named, it is a
        // two-minute fix in Google Cloud Console.
        // The SDK rejects with the NUMERIC status as a string (ErrorDto.kt:
        // `code = codeInt.toString()`), so this is '10', not 'DEVELOPER_ERROR'.
        // The name only appears in `message`. Both are matched so a future SDK
        // that switches to names does not silently fall through again.
        case DEVELOPER_ERROR_STATUS:
        case 'DEVELOPER_ERROR':
          throw new GoogleSignInUnavailable(
            __DEV__
              ? "Google rejected this build (DEVELOPER_ERROR): no Android OAuth client is registered for package in.dealdirect.mobile with this build's signing SHA-1. Add one in Google Cloud Console."
              : 'Google sign-in is not available in this build. Please sign in with email instead.'
          );
        default:
          break;
      }

      // Anything else: keep the generic line for users, but never hide the
      // SDK's own code from a developer again.
      throw new GoogleSignInUnavailable(
        __DEV__
          ? `Could not reach Google (${String(error.code)}: ${error.message ?? 'no message'}).`
          : 'Could not reach Google. Please try again.'
      );
    }

    throw new GoogleSignInUnavailable('Could not reach Google. Please try again.');
  }
}

/**
 * Clears the SDK's cached account so the next sign-in asks again.
 *
 * Called on app sign-out. Without it the Google session outlives the DealDirect
 * one, and the next person to open the app on a shared device is offered the
 * previous user's account as the obvious choice.
 */
export async function forgetGoogleAccount(): Promise<void> {
  if (!isGoogleSignInConfigured()) return;

  try {
    ensureConfigured();
    await loadSdk()!.GoogleSignin.signOut();
  } catch {
    // Best effort. Failing to clear a cache must never block signing out of
    // the app, which is the thing the user actually asked for.
  }
}
