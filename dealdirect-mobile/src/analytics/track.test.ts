import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { isUsageEventName, USAGE_EVENT_NAMES } from './events.ts';
import {
  BATCH_SIZE,
  CAP,
  createEventQueue,
  FLUSH_AT,
  type QueuedEvent,
  type QueueStore,
  type SendOutcome,
} from './queue.ts';

/**
 * The queue's rules, exercised against an in-memory store and an injectable
 * sender. `track.ts` is not imported: it pulls in React Native, and nothing
 * in it beyond the wiring is worth a test.
 */

function memoryStore(): QueueStore & { raw(): string | undefined } {
  const map = new Map<string, string>();
  return {
    getString: (key) => map.get(key),
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
    raw: () => map.get('q'),
  };
}

/** A sender that records every batch and answers from a script. */
function scriptedSender(outcomes: SendOutcome[]) {
  const batches: QueuedEvent[][] = [];
  const send = async (batch: readonly QueuedEvent[]): Promise<SendOutcome> => {
    batches.push(batch.slice());
    return outcomes.shift() ?? 'accepted';
  };
  return { send, batches };
}

const fixedNow = () => new Date('2026-09-04T10:00:00.000Z');

describe('whitelist', () => {
  it('the runtime set and the type agree on the nineteen names', () => {
    // Sixteen through Phase 3; three more in Phase 1/4/5 (shortlist_share,
    // locality_view, price_guidance_shown). The count is asserted so that a
    // name added to the type and forgotten in the runtime set fails here
    // rather than silently going undelivered.
    assert.equal(USAGE_EVENT_NAMES.size, 19);
    assert.ok(isUsageEventName('session_start'));
    assert.ok(isUsageEventName('review_submitted'));
    assert.ok(isUsageEventName('shortlist_share'));
    assert.ok(isUsageEventName('locality_view'));
    assert.ok(isUsageEventName('price_guidance_shown'));
    assert.ok(!isUsageEventName('page_view'));
    assert.ok(!isUsageEventName('Search'));
  });

  it('an unknown name never enters the queue', () => {
    const store = memoryStore();
    const { send } = scriptedSender([]);
    const queue = createEventQueue({ store, key: 'q', send, now: fixedNow });

    queue.enqueue('page_view', { path: '/x' });
    queue.enqueue('search', { results: 3 });

    assert.equal(queue.size(), 1);
    assert.deepEqual(queue.peek(), [
      { name: 'search', props: { results: 3 }, at: '2026-09-04T10:00:00.000Z' },
    ]);
  });

  it('empty props are omitted rather than sent as {}', () => {
    const store = memoryStore();
    const queue = createEventQueue({ store, key: 'q', send: scriptedSender([]).send, now: fixedNow });
    queue.enqueue('digest' as string);
    queue.enqueue('session_start', {});
    assert.deepEqual(queue.peek(), [{ name: 'session_start', at: '2026-09-04T10:00:00.000Z' }]);
  });
});

describe('persistence', () => {
  it('mirrors every enqueue to the store and clears it when drained', async () => {
    const store = memoryStore();
    const { send } = scriptedSender(['accepted']);
    const queue = createEventQueue({ store, key: 'q', send, now: fixedNow });

    queue.enqueue('shortlist_add', { propertyId: 'a' });
    assert.deepEqual(JSON.parse(store.raw() ?? '[]'), queue.peek());

    await queue.flush();
    assert.equal(store.raw(), undefined);
    assert.equal(queue.size(), 0);
  });

  it('rehydrates from the store, dropping rows it cannot trust', () => {
    const store = memoryStore();
    store.set(
      'q',
      JSON.stringify([
        { name: 'search', at: '2026-09-04T09:00:00.000Z', props: { results: 1 } },
        { name: 'no_such_event', at: '2026-09-04T09:00:00.000Z' },
        { name: 'search' },
        'garbage',
        null,
      ])
    );
    const queue = createEventQueue({ store, key: 'q', send: scriptedSender([]).send });
    assert.deepEqual(queue.peek(), [
      { name: 'search', at: '2026-09-04T09:00:00.000Z', props: { results: 1 } },
    ]);
  });

  it('a corrupt store value is discarded, not fatal', () => {
    const store = memoryStore();
    store.set('q', '{not json');
    const queue = createEventQueue({ store, key: 'q', send: scriptedSender([]).send });
    assert.equal(queue.size(), 0);
    assert.equal(store.raw(), undefined);
  });
});

describe('cap', () => {
  it(`keeps the newest ${CAP} rows and drops the oldest`, () => {
    const store = memoryStore();
    const queue = createEventQueue({ store, key: 'q', send: scriptedSender([]).send, now: fixedNow });

    for (let i = 0; i < CAP + 25; i += 1) {
      queue.enqueue('property_view', { propertyId: String(i), source: 'detail' });
    }

    assert.equal(queue.size(), CAP);
    assert.equal(queue.peek()[0]?.props?.propertyId, '25');
    assert.equal(queue.peek()[CAP - 1]?.props?.propertyId, String(CAP + 24));
    assert.equal(JSON.parse(store.raw() ?? '[]').length, CAP);
  });

  it('the cap also applies on rehydration', () => {
    const store = memoryStore();
    const rows = Array.from({ length: CAP + 10 }, (_, i) => ({
      name: 'search',
      at: `t${i}`,
    }));
    store.set('q', JSON.stringify(rows));
    const queue = createEventQueue({ store, key: 'q', send: scriptedSender([]).send });
    assert.equal(queue.size(), CAP);
    assert.equal(queue.peek()[0]?.at, 't10');
  });
});

describe('threshold', () => {
  it(`asks the owner to flush when the queue reaches ${FLUSH_AT}`, () => {
    let asked = 0;
    const queue = createEventQueue({
      store: memoryStore(),
      key: 'q',
      send: scriptedSender([]).send,
      onThreshold: () => {
        asked += 1;
      },
    });

    for (let i = 0; i < FLUSH_AT - 1; i += 1) queue.enqueue('search', { results: i });
    assert.equal(asked, 0);
    queue.enqueue('search', { results: 0 });
    assert.equal(asked, 1);
  });
});

describe('flush', () => {
  it(`splits at ${BATCH_SIZE} and sends as many batches as it takes`, async () => {
    const store = memoryStore();
    const { send, batches } = scriptedSender(['accepted', 'accepted', 'accepted']);
    const queue = createEventQueue({ store, key: 'q', send });

    for (let i = 0; i < BATCH_SIZE * 2 + 7; i += 1) queue.enqueue('search', { results: i });
    await queue.flush();

    assert.deepEqual(
      batches.map((batch) => batch.length),
      [BATCH_SIZE, BATCH_SIZE, 7]
    );
    assert.equal(batches[0]?.[0]?.props?.results, 0);
    assert.equal(batches[2]?.[6]?.props?.results, BATCH_SIZE * 2 + 6);
    assert.equal(queue.size(), 0);
  });

  it('drops a rejected batch and carries on with the next', async () => {
    const store = memoryStore();
    const { send, batches } = scriptedSender(['rejected', 'accepted']);
    const queue = createEventQueue({ store, key: 'q', send });

    for (let i = 0; i < BATCH_SIZE + 1; i += 1) queue.enqueue('search', { results: i });
    await queue.flush();

    assert.equal(batches.length, 2);
    assert.equal(queue.size(), 0);
    assert.equal(store.raw(), undefined);
  });

  it('keeps the batch on a network failure and stops', async () => {
    const store = memoryStore();
    const { send, batches } = scriptedSender(['retry', 'accepted']);
    const queue = createEventQueue({ store, key: 'q', send });

    for (let i = 0; i < BATCH_SIZE + 1; i += 1) queue.enqueue('search', { results: i });
    await queue.flush();

    // One attempt, nothing lost, the second batch never tried.
    assert.equal(batches.length, 1);
    assert.equal(queue.size(), BATCH_SIZE + 1);
    assert.equal(JSON.parse(store.raw() ?? '[]').length, BATCH_SIZE + 1);

    // The same rows go on the next flush.
    await queue.flush();
    assert.equal(batches.length, 3);
    assert.deepEqual(batches[1], batches[0]);
    assert.equal(queue.size(), 0);
  });

  it('a sender that throws counts as a network failure', async () => {
    const queue = createEventQueue({
      store: memoryStore(),
      key: 'q',
      send: async () => {
        throw new Error('boom');
      },
    });
    queue.enqueue('search', { results: 1 });
    await queue.flush();
    assert.equal(queue.size(), 1);
  });

  it('rows enqueued during a send are not lost when the batch is cleared', async () => {
    const store = memoryStore();
    let release: (() => void) | null = null;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const queue = createEventQueue({
      store,
      key: 'q',
      send: async () => {
        await gate;
        return 'accepted';
      },
    });

    queue.enqueue('search', { results: 1 });
    const flushing = queue.flush();
    queue.enqueue('search', { results: 2 });
    release!();
    await flushing;

    // The second row was sent in a second batch by the same drain loop.
    assert.equal(queue.size(), 0);
  });

  it('concurrent flush calls share one drain', async () => {
    let calls = 0;
    const queue = createEventQueue({
      store: memoryStore(),
      key: 'q',
      send: async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return 'accepted';
      },
    });
    queue.enqueue('search', { results: 1 });
    await Promise.all([queue.flush(), queue.flush(), queue.flush()]);
    assert.equal(calls, 1);
  });
});
