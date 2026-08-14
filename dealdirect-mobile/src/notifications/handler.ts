import type * as NotificationsModule from 'expo-notifications';

import { optionalNativeModule } from '@/config/optionalNative';
import { prefsStorage, PREF_KEYS } from '@/storage';

/**
 * Local-notification presentation and permission (M13).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS NOT
 *
 * There is no server-initiated push here. `expo-notifications` needs a
 * device push token registered with a backend that can address it (FCM/APNs),
 * and this backend has no device-token model, no push service credentials,
 * and no route to register one — confirmed absent in the architecture audit
 * (`MOBILE_APP_ARCHITECTURE_PLAN.md` §0, finding #6). That is a genuine
 * backend addition, tracked as a separate change request, and nothing in this
 * file assumes it exists.
 *
 * What IS built: presenting a LOCAL notification (this device, this process)
 * the moment a `receive_message` socket event arrives, so a new chat message
 * is visible even when the recipient is on a different screen. Because
 * `SocketProvider` deliberately disconnects the socket on background (M6),
 * this only ever fires while the app is in the foreground — there is no
 * connection alive to receive an event from otherwise. That is a narrower
 * claim than "push notifications," and the UI never implies more than that.
 *
 * ---------------------------------------------------------------------------
 * OPTIONAL, AND FOR AN IRONIC REASON
 *
 * `expo-notifications`' entry point imports `getDevicePushTokenAsync`, which
 * reaches for the native `ExpoPushTokenManager` at module scope. Expo Go does
 * not provide it, so the WHOLE package fails to load — including the local
 * notification API this file uses, which needs no push token at all. There is
 * no way to import the half we want without the half we do not.
 *
 * That failure was not contained: this module is re-exported by
 * `notifications/index`, which `app/_layout.tsx` imports for `PushBridge`. So
 * a missing push-token module took down the root layout, `AuthProvider` never
 * mounted, and every route reported an auth error instead. See
 * `config/optionalNative.ts`.
 *
 * Absent, every function here becomes a no-op. Chat still works; a message
 * arriving while you are on another screen simply does not raise a banner.
 */

const Notifications = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-notifications') as typeof NotificationsModule,
  'expo-notifications',
  'In-app notification banners for new chat messages are disabled.'
);

/** Exported so `PushBridge` can skip its listener rather than re-resolving. */
export const canNotify = Notifications !== null;

Notifications?.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowBanner: true,
    shouldShowList: true,
    shouldPlaySound: true,
    shouldSetBadge: false,
  }),
});

/**
 * Requests the OS notification permission at most once ever, tracked in
 * `prefsStorage` (survives logout — this is a device preference, not account
 * data, matching the existing convention for theme/recent-searches). Callers
 * decide the moment; this only enforces "don't ask again after the first
 * answer," which is what keeps this from re-prompting on every app open if
 * the user said no.
 */
export async function requestNotificationPermissionOnce(): Promise<void> {
  // Deliberately BEFORE the "already asked" flag is written: a host that
  // cannot ask must not burn the one-and-only prompt, or a later real build
  // would stay silent forever because Expo Go recorded an answer nobody gave.
  if (!Notifications) return;

  if (prefsStorage.getString(PREF_KEYS.notificationPermissionAsked)) return;

  try {
    await Notifications.requestPermissionsAsync();
  } finally {
    prefsStorage.set(PREF_KEYS.notificationPermissionAsked, '1');
  }
}

export interface LocalNotificationData {
  kind: 'chat';
  conversationId: string;
}

export async function presentLocalNotification(params: {
  title: string;
  body: string;
  data: LocalNotificationData;
}): Promise<void> {
  if (!Notifications) return;

  const { status } = await Notifications.getPermissionsAsync();
  if (status !== 'granted') return;

  await Notifications.scheduleNotificationAsync({
    content: {
      title: params.title,
      body: params.body,
      data: params.data as unknown as Record<string, unknown>,
    },
    trigger: null,
  });
}
