import type * as LocalAuthModule from 'expo-local-authentication';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * Biometric confirmation.
 *
 * ---------------------------------------------------------------------------
 * THIS IS NOT AUTHENTICATION. IT IS CONFIRMATION.
 *
 * The server is the only thing that authenticates a user in this app, from a
 * cookie it mints and can revoke. A fingerprint on the device proves the phone
 * is in its owner's hands; it proves nothing to the backend and grants no
 * access on its own. So biometrics are used here for exactly two things:
 *
 *   1. An optional app-lock — a local gate in front of an already-valid
 *      session, for a shared or lost phone.
 *   2. A confirm step before the two irreversible acts: deleting the account
 *      and revoking a session. The server still requires the password for
 *      deletion (it must, and does); this only adds a physical check that the
 *      person holding the phone meant to do it.
 *
 * It never replaces the password on a sensitive action, because a biometric
 * that could stand in for the password would be a way to delete an account
 * from an unlocked phone with no secret. See `settings/delete-account`.
 *
 * ---------------------------------------------------------------------------
 * ABSENCE AND OPT-OUT BOTH DEGRADE TO "SKIP THE CHECK"
 *
 * A host without the module, a device with no enrolled biometric, and a user
 * who never turned the app-lock on are all the same outcome: the extra check
 * does not happen and the flow proceeds on its other guarantees (the session,
 * the password). A confirmation the device cannot perform must not become a
 * wall the user cannot pass.
 */

const LocalAuth = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-local-authentication') as typeof LocalAuthModule,
  'expo-local-authentication',
  'Biometric confirmation is unavailable in this host.'
);

export const biometricsModuleAvailable = LocalAuth !== null;

/**
 * Whether this device can actually prompt: the module is present, the hardware
 * exists, AND a biometric is enrolled. All three are required — a phone with a
 * fingerprint reader the user never set up cannot authenticate.
 */
export async function isBiometricReady(): Promise<boolean> {
  if (!LocalAuth) return false;
  try {
    const [hasHardware, isEnrolled] = await Promise.all([
      LocalAuth.hasHardwareAsync(),
      LocalAuth.isEnrolledAsync(),
    ]);
    return hasHardware && isEnrolled;
  } catch {
    return false;
  }
}

/**
 * Prompts, and resolves to whether the user passed.
 *
 * Returns `true` when the device cannot prompt at all, and that is deliberate:
 * a caller uses this to GATE a confirmation, and a device with no biometric
 * must not be locked out of confirming — it falls through to whatever other
 * check the flow already has (the typed phrase, the password). The one place
 * that must NOT treat absence as success is the app-lock, which checks
 * `isBiometricReady` first and only arms itself when a real biometric exists.
 */
export async function confirmWithBiometrics(reason: string): Promise<boolean> {
  if (!LocalAuth) return true;

  const ready = await isBiometricReady();
  if (!ready) return true;

  try {
    const result = await LocalAuth.authenticateAsync({
      promptMessage: reason,
      // Let the OS offer the device passcode as a fallback, so a transient
      // fingerprint failure is not a dead end.
      disableDeviceFallback: false,
      cancelLabel: 'Cancel',
    });
    return result.success;
  } catch {
    // A thrown prompt (module torn down mid-call) falls through rather than
    // trapping the user. The flow's real guarantee is elsewhere.
    return true;
  }
}

/**
 * The strict variant, for the app-lock only.
 *
 * Here absence and failure both mean "not unlocked", because the whole point of
 * the lock is to withhold the app until the check passes. The caller arms this
 * only after `isBiometricReady` returned true, so "the device cannot prompt" is
 * not a state this should reach.
 */
export async function unlockWithBiometrics(reason: string): Promise<boolean> {
  if (!LocalAuth) return false;
  try {
    const result = await LocalAuth.authenticateAsync({
      promptMessage: reason,
      disableDeviceFallback: false,
      cancelLabel: 'Cancel',
    });
    return result.success;
  } catch {
    return false;
  }
}
