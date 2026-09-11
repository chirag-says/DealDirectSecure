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

import {
  GoogleSignin,
  isErrorWithCode,
  isSuccessResponse,
  statusCodes,
} from '@react-native-google-signin/google-signin';

import { GOOGLE_IOS_CLIENT_ID, GOOGLE_WEB_CLIENT_ID } from '@/config/env';

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
  return GOOGLE_WEB_CLIENT_ID.length > 0;
}

let configured = false;

function ensureConfigured(): void {
  if (configured) return;

  GoogleSignin.configure({
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
  if (!isGoogleSignInConfigured()) {
    throw new GoogleSignInUnavailable('Google sign-in is not available in this build.');
  }

  ensureConfigured();

  try {
    // Android only, and a no-op elsewhere. A device without current Play
    // Services shows the system update prompt rather than failing silently.
    await GoogleSignin.hasPlayServices({ showPlayServicesUpdateDialog: true });

    // Signing out first makes the account picker appear every time. Without
    // it the SDK silently reuses the last account, so a user with two Google
    // accounts on the phone cannot switch, and someone handed a friend's
    // device signs into the friend's account without being asked.
    await GoogleSignin.signOut();

    const response = await GoogleSignin.signIn();

    if (!isSuccessResponse(response)) {
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

    if (isErrorWithCode(error)) {
      switch (error.code) {
        case statusCodes.SIGN_IN_CANCELLED:
          throw new GoogleSignInCancelled();
        case statusCodes.IN_PROGRESS:
          // A second tap while the first sheet is still opening.
          throw new GoogleSignInCancelled();
        case statusCodes.PLAY_SERVICES_NOT_AVAILABLE:
          throw new GoogleSignInUnavailable(
            'Google Play Services is not available on this device. Please sign in with email instead.'
          );
        default:
          break;
      }
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
    await GoogleSignin.signOut();
  } catch {
    // Best effort. Failing to clear a cache must never block signing out of
    // the app, which is the thing the user actually asked for.
  }
}
