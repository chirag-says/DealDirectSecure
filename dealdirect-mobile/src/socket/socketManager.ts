import { useSyncExternalStore } from 'react';
import { io, type Socket } from 'socket.io-client';

import { call, chatEndpoints } from '@/api';
import { SOCKET_URL } from '@/config/env';
import type {
  ClientToServerEvents,
  ServerToClientEvents,
  SendMessagePayload,
  StopTypingPayload,
  TypingPayload,
} from './types';

/**
 * The one Socket.IO connection for the whole app.
 *
 * A plain module, not a React hook or a context value — this file owns a
 * single long-lived instance across the entire authenticated session, and
 * every screen reads it through the `use*` hooks at the bottom rather than
 * creating its own. `SocketProvider` only drives the lifecycle (connect on
 * auth + foreground, disconnect on background); it holds no state of its own.
 *
 * ---------------------------------------------------------------------------
 * THE HANDSHAKE IS APP-LEVEL, SO IT RUNS ON EVERY `connect`, NOT JUST THE FIRST
 *
 * `GET /chat/socket-token` mints a JWT valid for five minutes. Caching it
 * across reconnects would mean authenticating with a token that is very
 * likely expired by the time a background/foreground cycle reconnects, so it
 * is re-fetched from scratch every single time the transport connects —
 * first connect and every automatic reconnect alike, both of which fire
 * Socket.IO's own `connect` event.
 *
 * Socket.IO's built-in reconnection (capped exponential backoff) is left
 * enabled and handles transport-level drops for free. What it cannot handle
 * is OUR handshake: a fresh `connect` only means the transport is back, not
 * that this socket is authenticated, so nothing joins a room or sends
 * anything until `authenticated` arrives.
 *
 * ---------------------------------------------------------------------------
 * "DO NOT RETRY BLINDLY" ON auth_error
 *
 * A wrong or expired token is not a transport problem, and reconnecting the
 * transport again would just present the same bad token again. So a
 * consecutive `auth_error` gets exactly one retry (a fresh token fetch, since
 * the first one may have raced an expiry), and a second consecutive failure
 * calls `onSessionFailure` and stops — deliberately, via `socket.disconnect()`,
 * which also halts Socket.IO's own auto-reconnect loop. The real session
 * cookie might still be fine; `onSessionFailure` is wired by `SocketProvider`
 * to `refreshUser()`, which is the only way to find out. If that confirms the
 * session is alive, the next foreground/auth transition calls `connectSocket`
 * again and the failure counter starts over — it resets at the top of every
 * `connect`, not only on success, so one bad connection never poisons the
 * next.
 */

export type SocketStatus =
  | 'idle'
  | 'connecting'
  | 'authenticating'
  | 'ready'
  | 'reconnecting'
  | 'auth_failed';

interface ManagerSnapshot {
  status: SocketStatus;
  onlineUserIds: ReadonlySet<string>;
}

let snapshot: ManagerSnapshot = { status: 'idle', onlineUserIds: new Set() };
const listeners = new Set<() => void>();

function setSnapshot(next: Partial<ManagerSnapshot>): void {
  snapshot = { ...snapshot, ...next };
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): ManagerSnapshot {
  return snapshot;
}

type AppSocket = Socket<ServerToClientEvents, ClientToServerEvents>;

let socket: AppSocket | null = null;
let authFailureCount = 0;
let onSessionFailure: (() => void) | null = null;

async function runHandshake(): Promise<void> {
  if (!socket) return;

  authFailureCount = 0;
  setSnapshot({ status: 'authenticating' });

  try {
    const response = await call(chatEndpoints.socketToken);
    // A background/foreground cycle or a slow response could land after the
    // socket was torn down. Emitting on a disconnected instance is silently
    // dropped by Socket.IO, but the guard makes that explicit rather than
    // relying on it.
    if (socket?.connected) socket.emit('authenticate', { token: response.token });
  } catch {
    // The token endpoint itself failed (offline, 401, 5xx). Treated the same
    // as an auth_error: one retry, then a session failure.
    handleAuthFailure();
  }
}

function handleAuthFailure(): void {
  authFailureCount += 1;

  if (authFailureCount < 2) {
    void runHandshake();
    return;
  }

  setSnapshot({ status: 'auth_failed' });
  socket?.disconnect();
  onSessionFailure?.();
}

/**
 * Connects, or reconnects, the shared socket.
 *
 * Idempotent by design: called from two independent effects (the auth
 * transition and the AppState listener) that can both fire around the same
 * moment, and neither needs to coordinate with the other because calling this
 * twice in a row is harmless.
 */
export function connectSocket(callbacks: { onSessionFailure: () => void }): void {
  onSessionFailure = callbacks.onSessionFailure;

  if (socket) {
    if (!socket.connected) socket.connect();
    return;
  }

  setSnapshot({ status: 'connecting' });

  socket = io(SOCKET_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 15000,
    // Capped, not infinite: a session that is genuinely dead should not retry
    // forever in the background burning battery. auth_failed stops it sooner
    // in the common case; this is the backstop for pure transport failures.
    reconnectionAttempts: 30,
  });

  socket.on('connect', () => {
    void runHandshake();
  });

  socket.on('authenticated', () => {
    authFailureCount = 0;
    setSnapshot({ status: 'ready' });
  });

  socket.on('auth_error', () => {
    handleAuthFailure();
  });

  socket.on('error', (payload) => {
    // No correlation id on this event — see types.ts. Logged for diagnostics
    // only; nothing here can attribute it to a specific in-flight action, and
    // REST remains the source of truth regardless of what this event means.
    console.warn('[Socket] error event:', payload);
  });

  socket.on('disconnect', (reason) => {
    // A manual `.disconnect()` call (backgrounding, or the hard stop above)
    // reports this exact reason and does NOT trigger Socket.IO's own
    // reconnection loop. Anything else was a real drop, and reconnection is
    // already in progress by the time this fires.
    if (reason === 'io client disconnect') {
      setSnapshot({ status: 'idle', onlineUserIds: new Set() });
    } else {
      setSnapshot({ status: 'reconnecting' });
    }
  });

  socket.on('users_online', (userIds) => {
    setSnapshot({ onlineUserIds: new Set(userIds) });
  });
}

/**
 * Disconnects the shared socket.
 *
 * `destroy: true` (logout) tears the instance down completely so a later
 * login starts from nothing rather than reusing listeners or state from a
 * different account. The default (backgrounding) keeps the instance and only
 * calls `.disconnect()`, which is cheap to reverse with a plain `.connect()`
 * and does not need the handshake rebuilt from scratch at the socket.io-client
 * layer — only at the app layer, which `runHandshake` already re-does on every
 * `connect` event regardless.
 */
export function disconnectSocket(options: { destroy?: boolean } = {}): void {
  if (!socket) return;

  if (options.destroy) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
    authFailureCount = 0;
    onSessionFailure = null;
    setSnapshot({ status: 'idle', onlineUserIds: new Set() });
    return;
  }

  socket.disconnect();
}

function emit<Name extends keyof ClientToServerEvents>(
  name: Name,
  ...args: Parameters<ClientToServerEvents[Name]>
): void {
  // Silently dropped when not ready. REST is the source of truth for every
  // one of these; a missed join, typing pulse, or fan-out emit degrades the
  // live layer, not correctness.
  if (snapshot.status !== 'ready' || !socket?.connected) return;
  (socket.emit as (...a: unknown[]) => void)(name, ...args);
}

export function joinConversation(conversationId: string): void {
  emit('join_conversation', conversationId);
}

export function leaveConversation(conversationId: string): void {
  emit('leave_conversation', conversationId);
}

/** `message` should be the object `POST /chat/message/send` already returned. */
export function emitSendMessage(payload: SendMessagePayload): void {
  emit('send_message', payload);
}

export function emitTyping(payload: TypingPayload): void {
  emit('typing', payload);
}

export function emitStopTyping(payload: StopTypingPayload): void {
  emit('stop_typing', payload);
}

/**
 * Subscribes to one server event for as long as the caller needs it, scoped
 * to the CURRENT socket instance at subscription time.
 *
 * Used by feature hooks (a mounted chat thread listening for `receive_message`,
 * for instance) rather than exposing the raw socket, so a hook does not have to
 * know whether a socket exists yet or re-subscribe itself across a reconnect —
 * `on`/`off` on a Socket.IO instance survive a transport reconnect, since the
 * JS object is the same across it. A logout `destroy`, which replaces the
 * instance, is the one case a long-lived subscriber would go stale; nothing in
 * this app holds one across a logout, since the screens that would are
 * unmounted well before that happens.
 */
export function onSocketEvent<Name extends keyof ServerToClientEvents>(
  name: Name,
  handler: ServerToClientEvents[Name]
): () => void {
  if (!socket) return () => {};

  socket.on(name, handler as never);
  return () => {
    socket?.off(name, handler as never);
  };
}

export function useSocketStatus(): SocketStatus {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot).status;
}

export function useOnlineUserIds(): ReadonlySet<string> {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot).onlineUserIds;
}

export function useIsUserOnline(userId: string | undefined): boolean {
  const online = useOnlineUserIds();
  return !!userId && online.has(userId);
}
