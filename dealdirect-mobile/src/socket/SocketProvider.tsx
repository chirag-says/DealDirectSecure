import { useEffect } from 'react';
import { AppState } from 'react-native';

import { useAuth } from '@/auth';
import { connectSocket, disconnectSocket } from './socketManager';

/**
 * Drives the shared socket's lifecycle. Holds no state and provides no
 * context value — every screen reads the connection through the `use*` hooks
 * in `socketManager`, which work with no provider present. This component's
 * only job is calling `connectSocket` / `disconnectSocket` at the right
 * moments, matching what the server actually expects of a mobile client:
 * connect only once authenticated, and treat backgrounding as a disconnect
 * rather than trying to keep a socket alive through OS suspension.
 *
 * Two independent effects, not one combined effect, because they react to
 * genuinely different triggers (an auth transition vs. a foreground/
 * background transition) that can each fire without the other. Both call into
 * idempotent functions, so overlapping fires from the two effects around the
 * same moment are harmless rather than something that needs coordinating.
 *
 * ---------------------------------------------------------------------------
 * WHERE IT IS MOUNTED (Phase 2, 2026-09-04)
 *
 * NOT at the root. D2 (HANDOFF §9.1) unmounted it there because a live socket
 * serving no UI is a cost with no benefit. It is now mounted by the deal page
 * (`app/deal/[leadId].tsx`), around the message wall only, and only when the
 * deal has a conversation. So the socket lives exactly while a thread is on
 * screen: the effect below connects on mount and DISCONNECTS on unmount (the
 * cleanup that was missing when this was a root-level, never-unmounting
 * component). The instance is kept, not destroyed, on that path: a second
 * deal page a moment later reconnects cheaply, and the handshake is redone
 * on every `connect` regardless.
 */
export function SocketProvider({ children }: { children: React.ReactNode }) {
  const { status, refreshUser } = useAuth();

  useEffect(() => {
    if (status !== 'authenticated') {
      // Also covers logout: a real account switch should not resume the
      // previous account's presence or room memberships.
      disconnectSocket({ destroy: true });
      return;
    }

    connectSocket({ onSessionFailure: () => void refreshUser() });
    return () => disconnectSocket();
  }, [status, refreshUser]);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => {
      if (status !== 'authenticated') return;

      if (next === 'active') {
        connectSocket({ onSessionFailure: () => void refreshUser() });
      } else {
        // `background` and `inactive` both mean "not something the user is
        // looking at right now" on iOS; treated the same as the plan requires
        // (disconnect on background), rather than trying to distinguish them.
        disconnectSocket();
      }
    });

    return () => subscription.remove();
  }, [status, refreshUser]);

  return <>{children}</>;
}
