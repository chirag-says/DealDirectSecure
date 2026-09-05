import type * as NotificationsModule from 'expo-notifications';
import { useRootNavigationState, useRouter } from 'expo-router';
import { useEffect } from 'react';

import { track } from '@/analytics';
import { optionalNativeModule } from '@/config/optionalNative';
import {
  hrefForTarget,
  readNotificationKind,
  resolveTargetFromData,
} from '@/features/notifications/targets';

/**
 * Routes a tapped push notification to its screen.
 *
 * Mounted once in the root layout, inside `AuthProvider`, rendering nothing.
 * Two entry points, one handler:
 *
 *   - `addNotificationResponseReceivedListener` for a tap while the app is
 *     running (foreground or background).
 *   - `getLastNotificationResponseAsync` for a tap that LAUNCHED the app: the
 *     listener is not yet attached when the OS delivers that response, so it
 *     has to be asked for after the fact.
 *
 * The two can report the same response (a warm-start tap arrives on the
 * listener AND is returned as "last"), and a Fast Refresh remounts this
 * component and asks for "last" again. So the handled id is kept at module
 * scope, not in a ref: a response is acted on once per process, full stop.
 *
 * Navigation waits for the root navigator: `router.push` before the Stack has
 * a state throws, and on a cold start the response is in hand before the tree
 * is. `useRootNavigationState().key` is the signal; the effect simply re-runs
 * when it appears.
 *
 * `data` is never trusted. It goes through `resolveTargetFromData`, which
 * reads `kind` against a closed vocabulary and validates every id as an
 * ObjectId; `hrefForTarget` is the single place a target becomes a route. A
 * payload that does not resolve is counted (`push_opened` still fires, with
 * whatever kind it named) and goes nowhere. No `actionUrl` is ever opened.
 */

const Notifications = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-notifications') as typeof NotificationsModule,
  'expo-notifications',
  'Tapping a push notification will open the app but not the screen it names.'
);

/** `request.identifier` of the last response acted on, per process. */
let handledResponseId: string | null = null;

export function PushRouter() {
  const router = useRouter();
  const navigationReady = !!useRootNavigationState()?.key;

  useEffect(() => {
    if (!Notifications || !navigationReady) return;

    const open = (response: NotificationsModule.NotificationResponse) => {
      const { identifier, content } = response.notification.request;
      if (handledResponseId === identifier) return;
      handledResponseId = identifier;

      const data: unknown = content.data;
      track('push_opened', { kind: readNotificationKind(data) ?? 'unknown' });

      const target = resolveTargetFromData(data);
      if (target) router.push(hrefForTarget(target));
    };

    void Notifications.getLastNotificationResponseAsync().then((response) => {
      if (response) open(response);
    });

    const subscription = Notifications.addNotificationResponseReceivedListener(open);
    return () => subscription.remove();
  }, [router, navigationReady]);

  return null;
}
