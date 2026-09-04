/**
 * Phase 0: the scheduler's bookkeeping (jobs/runner.js).
 *
 * The cron wiring is not under test (node-cron is a dependency, not our
 * code). What is: a run is recorded, the cursor flows from the last
 * successful run to the next, a crashed handler is recorded and does not
 * throw, an in-flight run blocks a second tick, and a stale in-flight run
 * (a crash mid-run) does not block forever.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders, pushBatchesSent, clearPushBatches } from './setup/fakeProviders.js';
import { makeUser } from './setup/factories.js';

import { runJob, lastSuccessfulRun } from '../../jobs/runner.js';
import { sendPush, collectReceipts, _pending } from '../../services/pushService.js';

const M = (name) => mongoose.model(name);

test.before(async () => { await request(); });
test.beforeEach(async () => { await truncateAll(); clearPushBatches(); _pending.clear(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

test('runJob', async (t) => {
  await t.test('records a successful run with its cursor and stats', async () => {
    const job = { name: 'demo', schedule: '* * * * *', handler: async ({ cursor }) => ({ cursor: { n: (cursor?.n || 0) + 1 }, touched: 3 }) };
    const first = await runJob(job, { now: new Date('2026-09-04T00:00:00Z') });
    assert.equal(first.ok, true);
    assert.deepEqual(first.cursor, { n: 1 });
    const second = await runJob(job, { now: new Date('2026-09-04T00:05:00Z') });
    assert.deepEqual(second.cursor, { n: 2 }, 'the cursor came from the previous successful run');
    const rows = await M('JobRun').find({ name: 'demo' }).sort({ startedAt: 1 }).lean();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].ok, true);
    assert.deepEqual(rows[0].stats, { touched: 3 });
    assert.ok(rows[1].finishedAt);
  });

  await t.test('a throwing handler is recorded as failed and does not throw; the cursor does not advance', async () => {
    let calls = 0;
    const job = {
      name: 'flaky',
      schedule: '* * * * *',
      handler: async () => {
        calls += 1;
        if (calls === 1) throw new Error('boom');
        return { cursor: 'after' };
      },
    };
    const failed = await runJob(job, { now: new Date('2026-09-04T00:00:00Z') });
    assert.equal(failed.ok, false);
    assert.match(failed.error, /boom/);
    assert.equal(await lastSuccessfulRun('flaky'), null);
    const row = await M('JobRun').findOne({ name: 'flaky' }).lean();
    assert.equal(row.ok, false);
    assert.equal(row.error, 'boom');

    const ok = await runJob(job, { now: new Date('2026-09-04T00:05:00Z') });
    assert.equal(ok.ok, true);
    assert.equal((await lastSuccessfulRun('flaky')).cursor, 'after');
  });

  await t.test('a younger in-flight run blocks the tick; a stale one does not', async () => {
    const job = { name: 'slow', schedule: '* * * * *', handler: async () => ({}), staleAfterMs: 10 * 60 * 1000 };
    const now = new Date('2026-09-04T01:00:00Z');
    await M('JobRun').create({ name: 'slow', startedAt: new Date(now.getTime() - 60 * 1000), finishedAt: null });
    const blocked = await runJob(job, { now });
    assert.equal(blocked.skipped, 'in-flight');

    await M('JobRun').deleteMany({});
    await M('JobRun').create({ name: 'slow', startedAt: new Date(now.getTime() - 30 * 60 * 1000), finishedAt: null });
    const ran = await runJob(job, { now });
    assert.equal(ran.ok, true);
  });

  await t.test('the handler receives the clock it is given, never Date.now', async () => {
    let seen = null;
    const job = { name: 'clock', schedule: '* * * * *', handler: async ({ now }) => { seen = now; return {}; } };
    const fixed = new Date('2030-01-01T00:00:00Z');
    await runJob(job, { now: fixed });
    assert.equal(seen.getTime(), fixed.getTime());
  });
});

test('push receipts', async (t) => {
  await t.test('tickets are remembered and receipts are collected by the job', async () => {
    const user = await makeUser();
    await M('PushToken').create({ user: user._id, token: 'ExponentPushToken[receiptreceiptreceipt1]', platform: 'android' });
    const sent = await sendPush([{ userId: user._id, title: 't', body: 'b' }]);
    assert.equal(sent.sent, 1);
    assert.equal(_pending.size, 1);
    const result = await collectReceipts();
    assert.equal(result.checked, 1);
    assert.equal(result.disabled, 0);
    assert.equal(_pending.size, 0);
    const again = await collectReceipts();
    assert.equal(again.checked, 0, 'nothing pending, nothing asked');
  });
});
