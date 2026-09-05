import type * as NotificationsModule from 'expo-notifications';
import Constants from 'expo-constants';
import { Platform } from 'react-native';

import { getInstallationId } from '@/analytics/installationId';
import { call, usersEndpoints } from '@/api';
import { APP_VERSION } from '@/config/env';
import { optionalNativeModule } from '@/config/optionalNative';
import { PREF_KEYS, prefsStorage } from '@/storage';
import type { PushPlatform } from '@/types/backend/user';

/**
 * The device push token's lifecycle (Phase 0).
 *
 * The backend now has a push-token model and `POST/DELETE /users/push-token`
 * (this is the addition `handler.ts` records as absent; that note is history
 * now, not a description). This file is the only place the token is read,
 * sent or forgotten.
 *
 * ---------------------------------------------------------------------------
 * THIS NEVER PROMPTS
 *
 * Registration happens only when the OS permission is ALREADY granted. The
 * prompt itself is `requestNotificationPermissionOnce()` (`handler.ts`), and
 * the product decision about WHEN belongs to the call sites: the first
 * shortlist add and the first saved-search create, never launch. A permission
 * asked at launch, before the app has done anything for the user, is refused
 * by most people and can never be asked again.
 *
 * ---------------------------------------------------------------------------
 * WHO THE TOKEN BELONGS TO
 *
 * A push token identifies the INSTALL; the backend binds it to an ACCOUNT.
 * Re-posting the same token re-points it at whoever is signed in, so the cache
 * below is keyed on the user as well as the token: the same person on the same
 * phone skips a re-post for 24h, a different person on the same phone posts at
 * once. On sign-out the token goes in the logout body and the backend drops
 * it, so a shared or handed-on phone stops receiving the previous account's
 * notifications. Any session end, however caused, clears the cache.
 *
 * Every failure here is swallowed after a log line. A push token that failed
 * to register costs the user a notification; a thrown error costs them a
 * screen.
 */

const Notifications = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-notifications') as typeof NotificationsModule,
  'expo-notifications',
  'Push notifications will not reach this device.'
);

interface CachedPushToken {
  token: string;
  userId: string;
  /** Epoch ms of the last successful POST. */
  at: number;
}

/** How long a successful registration is trusted before it is re-posted. */
const REREGISTER_AFTER_MS = 24 * 60 * 60 * 1000;

/**
 * The account push registrations are made for. Set by `AuthProvider` as the
 * session comes and goes; `null` means guest, and registering as a guest is
 * impossible (the route needs the cookie), so the call sites in the shortlist
 * and saved-search flows need no auth plumbing of their own.
 */
let currentUserId: string | null = null;

export function setPushTokenUser(userId: string | null): void {
  currentUserId = userId;
}

function readCache(): CachedPushToken | null {
  const raw = prefsStorage.getString(PREF_KEYS.pushToken);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as Partial<CachedPushToken>;
    if (
      typeof parsed.token !== 'string' ||
      typeof parsed.userId !== 'string' ||
      typeof parsed.at !== 'number'
    ) {
      return null;
    }
    return { token: parsed.token, userId: parsed.userId, at: parsed.at };
  } catch {
    prefsStorage.remove(PREF_KEYS.pushToken);
    return null;
  }
}

/** The token the backend currently holds for this device, if this app told it one. */
export function peekCachedPushToken(): string | null {
  return readCache()?.token ?? null;
}

export function clearPushTokenCache(): void {
  prefsStorage.remove(PREF_KEYS.pushToken);
}

const PUSH_PLATFORM: PushPlatform | null =
  Platform.OS === 'ios' ? 'ios' : Platform.OS === 'android' ? 'android' : null;

/**
 * Registers this device's Expo push token for the signed-in user, if the OS
 * permission is granted. Never prompts. Safe to call often: it returns at
 * once for a guest, for a missing module, for a denied permission, and for a
 * token already posted for this user within the last 24 hours.
 */
export async function registerPushTokenIfPermitted(): Promise<void> {
  const userId = currentUserId;
  if (!Notifications || !userId || !PUSH_PLATFORM) return;

  try {
    const { status } = await Notifications.getPermissionsAsync();
    if (status !== 'granted') return;

    // Android 8+ delivers nothing without a channel. Expo's push service
    // targets `default` when a message names none, so it has to exist.
    // Idempotent; the OS ignores a repeat with the same settings.
    if (Platform.OS === 'android') {
      await Notifications.setNotificationChannelAsync('default', {
        name: 'Default',
        importance: Notifications.AndroidImportance.HIGH,
      });
    }

    const projectId = Constants.expoConfig?.extra?.eas?.projectId as string | undefined;
    const { data: token } = await Notifications.getExpoPushTokenAsync(
      projectId ? { projectId } : undefined
    );
    if (!token) return;

    const cached = readCache();
    if (
      cached &&
      cached.token === token &&
      cached.userId === userId &&
      Date.now() - cached.at < REREGISTER_AFTER_MS
    ) {
      return;
    }

    await call(usersEndpoints.registerPushToken, {
      data: {
        token,
        platform: PUSH_PLATFORM,
        installationId: getInstallationId(),
        appVersion: APP_VERSION,
      },
    });

    const record: CachedPushToken = { token, userId, at: Date.now() };
    prefsStorage.set(PREF_KEYS.pushToken, JSON.stringify(record));
  } catch (error) {
    console.warn('[push] token registration failed', error);
  }
}

/**
 * Tells the backend to forget this device's token, and forgets it locally.
 * Errors are swallowed: the local cache is cleared either way, because a
 * device that believes it is registered when it is not is the safer of the
 * two mistakes (it re-posts within a day).
 *
 * Not used by the ordinary sign-out path, which sends the token in the logout
 * body instead so the round trip is one request rather than two.
 */
export async function unregisterPushToken(): Promise<void> {
  const token = peekCachedPushToken();
  clearPushTokenCache();
  if (!token) return;

  try {
    await call(usersEndpoints.removePushToken, { data: { token } });
  } catch (error) {
    console.warn('[push] token removal failed', error);
  }
}
