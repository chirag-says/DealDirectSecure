import { call, usersEndpoints } from '@/api';
// The file, not the `@/analytics` barrel: the barrel pulls in `track.ts`,
// which is glue this module has no use for.
import { getInstallationId } from '@/analytics/installationId';
import { PREF_KEYS, prefsStorage } from '@/storage';

/**
 * Tells the backend which install this account is signing in from.
 *
 * `POST /users/device { deviceHash }` feeds ONE thing: the close-deal
 * fraud-linkage check (Phase 3), which asks whether the buyer and the owner
 * of a "closed" deal are the same phone. The hash is the analytics
 * installation id, an opaque per-install UUID that carries nothing about the
 * user; the server stores it against the account and nothing else reads it.
 *
 * Sent once per (install, account): `prefsStorage` remembers the user id it
 * was last sent for, and a session for the same user skips the call. The key
 * lives in prefs rather than user-scoped storage on purpose, since the fact
 * it records ("this install has been linked to account X") survives logout
 * and is still true at the next sign-in. A different account on the same
 * phone sends again, which is exactly the case the check exists for.
 *
 * Fire and forget. A failure is swallowed and the guard is NOT set, so the
 * next authenticated session tries again.
 */
export async function linkDeviceOnce(userId: string): Promise<void> {
  if (prefsStorage.getString(PREF_KEYS.deviceLinkedFor) === userId) return;

  try {
    await call(usersEndpoints.registerDevice, { data: { deviceHash: getInstallationId() } });
    prefsStorage.set(PREF_KEYS.deviceLinkedFor, userId);
  } catch {
    // Nothing the user can act on, and nothing the app depends on.
  }
}
