import { isUsageEventName } from './events.ts';

/**
 * The usage-event queue, with nothing React Native in it.
 *
 * `track.ts` owns the platform: the API call, `AppState`, the timer and MMKV.
 * This file owns the rules, and the rules are what need tests:
 *
 *   - names outside the whitelist are refused at the door
 *   - the queue is mirrored to a key-value store on every change, capped at
 *     `CAP` rows with the oldest dropped, so a kill loses nothing and a stuck
 *     loop cannot grow storage without bound
 *   - a flush sends at most `BATCH_SIZE` rows per request, as many requests as
 *     it takes
 *   - a batch the server REJECTS is dropped (it will be rejected again), a
 *     batch the server never RECEIVED is kept (it will be accepted later)
 *   - one flush at a time; a second call while one is running joins it
 *
 * The sender is injected, which is what makes the last three testable without
 * a network, and what keeps this module ignorant of axios.
 */

export interface QueuedEvent {
  name: string;
  props?: Record<string, unknown>;
  /** ISO-8601, captured at enqueue time. */
  at: string;
}

/**
 * What became of one batch.
 *
 *   accepted: the server took it (a 2xx, including the 202 it actually sends)
 *   rejected: the server refused it and would refuse it again (a 4xx)
 *   retry:    the server never had a say. No network, a timeout, a 5xx, or a
 *             429 that says "not now" rather than "not ever"
 */
export type SendOutcome = 'accepted' | 'rejected' | 'retry';

export type BatchSender = (batch: readonly QueuedEvent[]) => Promise<SendOutcome>;

/** The subset of `KeyValueStore` this queue needs. */
export interface QueueStore {
  getString(key: string): string | undefined;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export interface EventQueueOptions {
  store: QueueStore;
  key: string;
  send: BatchSender;
  /** Called when the queue reaches `flushAt`. The owner decides whether to flush now. */
  onThreshold?: () => void;
  cap?: number;
  batchSize?: number;
  flushAt?: number;
  now?: () => Date;
}

/** Rows kept on disk. Past this the OLDEST go, so the newest session survives. */
export const CAP = 200;
/** The backend's per-request maximum. */
export const BATCH_SIZE = 50;
/** Queue depth at which the owner is asked to flush without waiting for the timer. */
export const FLUSH_AT = 20;

export interface EventQueue {
  enqueue(name: string, props?: Record<string, unknown>): void;
  flush(): Promise<void>;
  /** A copy. For tests and diagnostics; nothing else should read the queue. */
  peek(): readonly QueuedEvent[];
  size(): number;
}

function isQueuedEvent(value: unknown): value is QueuedEvent {
  if (typeof value !== 'object' || value === null) return false;
  const row = value as Partial<QueuedEvent>;
  return typeof row.name === 'string' && typeof row.at === 'string';
}

export function createEventQueue(options: EventQueueOptions): EventQueue {
  const {
    store,
    key,
    send,
    onThreshold,
    cap = CAP,
    batchSize = BATCH_SIZE,
    flushAt = FLUSH_AT,
    now = () => new Date(),
  } = options;

  let rows: QueuedEvent[] = restore();
  let flushing: Promise<void> | null = null;

  function restore(): QueuedEvent[] {
    const raw = store.getString(key);
    if (!raw) return [];

    try {
      const parsed: unknown = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      // Validated per row: this data outlives app versions, and one bad row
      // must not blank the queue. A name this build no longer knows is dropped
      // here rather than sent for the server to drop.
      return parsed
        .filter(isQueuedEvent)
        .filter((row) => isUsageEventName(row.name))
        .slice(-cap);
    } catch {
      store.remove(key);
      return [];
    }
  }

  function persist(): void {
    if (rows.length === 0) {
      store.remove(key);
      return;
    }
    store.set(key, JSON.stringify(rows));
  }

  function enqueue(name: string, props?: Record<string, unknown>): void {
    if (!isUsageEventName(name)) return;

    const row: QueuedEvent = { name, at: now().toISOString() };
    if (props && Object.keys(props).length > 0) row.props = props;

    rows.push(row);
    if (rows.length > cap) rows = rows.slice(rows.length - cap);
    persist();

    if (rows.length >= flushAt) onThreshold?.();
  }

  async function drain(): Promise<void> {
    while (rows.length > 0) {
      const batch = rows.slice(0, batchSize);

      let outcome: SendOutcome;
      try {
        outcome = await send(batch);
      } catch {
        // A sender that throws is treated as "never received": the honest
        // reading of an exception nobody classified.
        outcome = 'retry';
      }

      if (outcome === 'retry') return;

      // Accepted or rejected, the batch is finished with. Rows enqueued while
      // the request was in flight sit AFTER the batch and are untouched.
      rows = rows.slice(batch.length);
      persist();
    }
  }

  function flush(): Promise<void> {
    if (flushing) return flushing;
    flushing = drain().finally(() => {
      flushing = null;
    });
    return flushing;
  }

  return {
    enqueue,
    flush,
    peek: () => rows.slice(),
    size: () => rows.length,
  };
}
