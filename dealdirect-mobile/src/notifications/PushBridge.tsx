import type * as NotificationsModule from 'expo-notifications';
import { useRouter } from 'expo-router';
import { useEffect } from 'react';

import { useAuth } from '@/auth';
import { optionalNativeModule } from '@/config/optionalNative';
import { getActiveConversationId, isMessageShape } from '@/features/chat';
import { decodeHtmlEntities } from '@/lib';
import { onSocketEvent, useSocketStatus } from '@/socket';
import type { LocalNotificationData } from './handler';
import { canNotify, presentLocalNotification } from './handler';

/**
 * Optional for the reason set out in `handler.ts`: the package's entry point
 * needs a native push-token module that Expo Go does not ship, so the whole
 * import fails. `canNotify` already recorded whether it resolved; this second
 * call is served from the same failed-module state and costs nothing.
 */
const Notifications = canNotify
  ? optionalNativeModule(
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      () => require('expo-notifications') as typeof NotificationsModule,
      'expo-notifications',
      'Tapping a notification will not deep-link into the conversation.'
    )
  : null;

/**
 * Bridges `receive_message` socket events to a local notification.
 *
 * Mounted once, inside the same authenticated/socket-connected tree as
 * `SocketProvider` — see `app/_layout.tsx`. Renders nothing.
 *
 * Two suppressions, both deliberate:
 *  - The sender's own messages never notify (obviously).
 *  - A message for the conversation currently open on screen never notifies
 *    either — the thread already shows it inline, and a banner on top of the
 *    exact content already visible is noise, not information. Tracked via
 *    `getActiveConversationId()`, set by the thread screen on focus/blur.
 */
export function PushBridge() {
  const router = useRouter();
  const { user } = useAuth();
  const socketStatus = useSocketStatus();

  useEffect(() => {
    const off = onSocketEvent('receive_message', (raw) => {
      if (!isMessageShape(raw)) return;
      if (raw.sender._id === user?._id) return;
      if (raw.conversation === getActiveConversationId()) return;

      void presentLocalNotification({
        title: raw.sender.name,
        body: decodeHtmlEntities(raw.text),
        data: { kind: 'chat', conversationId: raw.conversation },
      });
    });

    return off;
  }, [user?._id, socketStatus]);

  useEffect(() => {
    if (!Notifications) return;

    const subscription = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data as
        | Partial<LocalNotificationData>
        | undefined;

      if (data?.kind === 'chat' && typeof data.conversationId === 'string') {
        router.push(`/chat/${data.conversationId}`);
      }
    });

    return () => subscription.remove();
  }, [router]);

  return null;
}
