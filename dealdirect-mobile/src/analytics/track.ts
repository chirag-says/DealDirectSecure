import { AppState, type AppStateStatus, Platform } from 'react-native';

import { ApiError, call, eventsEndpoints } from '@/api';
import { PREF_KEYS, prefsStorage } from '@/storage';
import type { UsageEventName, UsageEvents } from './events.ts';
import { getInstallationId } from './installationId';
import { createEventQueue, type QueuedEvent, type SendOutcome } from './queue.ts';

/**
 * Usage events: `track()` at the call site, `POST /events` in batches.
 *
 * What this is for: the questions the master plan's Phase 0 exit asks (did a
 * first session reach a search, a listing, a shortlist?) cannot be answered
 * from the server's own logs, because the interesting moments (a shortlist
 * add, a screen view) never hit the server at all. So the app says what
 * happened, in a vocabulary the backend whitelists (`events.ts`).
 *
 * What it is NOT: a tracker. No device fingerprint, no ad id, no location, no
 * free text. Props are ids the backend already holds, and `anon` is a
 * per-install id that maps to nothing (`installationId.ts`). A signed-in
 * user's events carry the session cookie, so the server attributes them; a
 * guest's carry only `anon`.
 *
 * Delivery: rows are mirrored to MMKV on every enqueue so a kill loses none,
 * and flushed every `FLUSH_INTERVAL_MS` while foregrounded, on backgrounding,
 * and when the queue reaches `FLUSH_AT` (`queue.ts`). The timer flush is a
 * no-op on an empty queue, so an idle app makes no request; `/events` has its
 * own limiter (30 batches / min / IP) and never touches the 20/min search tier.
 *
 * The queue's rules (cap, batching, drop-on-reject, keep-on-retry) live in
 * `queue.ts` with no React Native in them, and that is where they are tested.
 */

const FLUSH_INTERVAL_MS = 30_000;

/**
 * `Platform.OS` is wider than the backend's `platform`. Web is not a shipping
 * target for this app, so anything that is not iOS reports as Android rather
 * than being dropped; if web ever ships, this is the line to revisit.
 */
const PLATFORM: 'android' | 'ios' = Platform.OS === 'ios' ? 'ios' : 'android';

async function sendBatch(batch: readonly QueuedEvent[]): Promise<SendOutcome> {
  try {
    await call(eventsEndpoints.ingest, {
      data: { events: batch.slice(), platform: PLATFORM, anon: getInstallationId() },
    });
    return 'accepted';
  } catch (error) {
    if (error instanceof ApiError && error.status !== undefined) {
      // A 429 is "not now", not "not ever": the batch would be accepted a
      // minute later, so it stays. Every other 4xx is a verdict on the batch
      // itself and re-sending it would only earn the same answer.
      if (error.status === 429) return 'retry';
      if (error.status >= 400 && error.status < 500) return 'rejected';
    }
    return 'retry';
  }
}

const queue = createEventQueue({
  store: prefsStorage,
  key: PREF_KEYS.analyticsQueue,
  send: sendBatch,
  onThreshold: () => void flushEvents(),
});

/**
 * Records one event. Synchronous and cheap: it appends to memory, mirrors to
 * disk, and returns. Nothing here awaits the network.
 */
export function track<N extends UsageEventName>(name: N, props: UsageEvents[N]): void {
  queue.enqueue(name, props);
}

export function flushEvents(): Promise<void> {
  if (queue.size() === 0) return Promise.resolve();
  return queue.flush();
}

let started = false;

/**
 * Starts the timer and the foreground/background bookkeeping. Called once from
 * the root layout; a second call is a no-op so Fast Refresh cannot stack
 * listeners.
 *
 * `session_start` fires here and on every return from the BACKGROUND state,
 * not on every transition to `active`: iOS passes through `inactive` for a
 * notification shade or a system dialog, and counting each of those as a new
 * session would make the metric describe the OS rather than the user.
 */
export function startAnalytics(): void {
  if (started) return;
  started = true;

  let timer: ReturnType<typeof setInterval> | null = null;
  let previous: AppStateStatus = AppState.currentState;

  const startTimer = () => {
    if (timer) return;
    timer = setInterval(() => void flushEvents(), FLUSH_INTERVAL_MS);
  };
  const stopTimer = () => {
    if (!timer) return;
    clearInterval(timer);
    timer = null;
  };

  track('session_start', { platform: PLATFORM });
  startTimer();

  AppState.addEventListener('change', (next) => {
    if (next === 'active' && previous === 'background') {
      track('session_start', { platform: PLATFORM });
      startTimer();
    } else if (next === 'background') {
      stopTimer();
      void flushEvents();
    }
    previous = next;
  });
}
