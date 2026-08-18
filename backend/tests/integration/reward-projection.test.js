/**
 * Suite 22: what a reward read actually loads (Phase 4.5).
 *
 * THE AUDIT FIRST, because it shrank the job considerably.
 *
 * Every Reward query in the backend, and whether it needs the transaction
 * array:
 *
 *   hubbleController:204  balance        NO  — already .select("availablePoints").lean()
 *   hubbleController:245  debit          YES — scans for a duplicate reference, then pushes
 *   hubbleController:327  reverse        YES — same
 *   rewardsController:37  getWallet      YES — returns recentTransactions
 *   rewardsController:53  history        YES — obviously
 *   rewardsController:307 admin wallet   YES — same function
 *   rewardsController     3 aggregates   NO  — already $project-ed server-side
 *   rewardService:263     awardPoints    YES — pushes
 *   rewardService:393     getWallet      YES
 *   rewardService:613     adminAdjust    YES — pushes
 *   rewardService:577     trackDailyLogin  NO — touches lastLoginDate only
 *   userController:378/453 registration   NO — the return value is discarded
 *
 * So the roadmap's premise, "loaded in full on every read", is mostly already
 * false: the balance check and the admin aggregates were projected before this
 * change. TWO paths load the array for nothing, and one of them —
 * trackDailyLogin — runs on every single login, which is what makes it worth
 * doing at all.
 *
 * THE RISK THIS SUITE EXISTS FOR. `trackDailyLogin` mutates the wallet and
 * calls `.save()`. Saving a document whose `transactions` path was never
 * loaded is exactly the shape of change that silently empties an array. The
 * test below writes transactions, tracks a login, and asserts they are still
 * there — it is the reason the projection is safe rather than merely faster.
 *
 * NOT DONE, deliberately: no cap, no archive, no separate collection, no
 * migration. Production holds 38 wallets with at most 71 transactions against a
 * 16 MB ceiling.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeUser } from './setup/factories.js';

import {
  getOrCreateWallet, getWallet, trackDailyLogin, awardPoints, getTransactionHistory,
} from '../../services/rewardService.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Reward = () => mongoose.model('Reward');

/** A wallet carrying real transaction history. */
async function walletWithHistory(n = 12) {
  const user = await makeUser();
  const wallet = await getOrCreateWallet(user._id);

  for (let i = 0; i < n; i += 1) {
    wallet.transactions.push({
      type: 'earn',
      action: 'FIXTURE',
      points: 10,
      description: `Fixture transaction ${i}`,
      createdAt: new Date(Date.now() - i * 1000),
    });
  }
  wallet.totalPoints = n * 10;
  wallet.availablePoints = n * 10;
  await wallet.save();

  return { user, wallet };
}

const raw = (userId) => Reward().findOne({ user: userId }).lean();

// ---------------------------------------------------------------------------

test('the summary paths no longer hydrate the array', async (t) => {
  await t.test('trackDailyLogin loads a wallet without transactions', async () => {
    const { user } = await walletWithHistory(12);

    const wallet = await getOrCreateWallet(user._id, { withTransactions: false });

    assert.equal(wallet.transactions?.length ?? 0, 0,
      'the array was hydrated on a path that never reads it');
    assert.ok(wallet.totalPoints > 0, 'the fields it DOES need must still be there');
  });

  await t.test('the full loader still hydrates them', async () => {
    const { user } = await walletWithHistory(12);
    const wallet = await getOrCreateWallet(user._id);
    assert.equal(wallet.transactions.length, 12);
  });

  await t.test('a summary load still carries points, tier and login state', async () => {
    const { user } = await walletWithHistory(5);
    const wallet = await getOrCreateWallet(user._id, { withTransactions: false });

    for (const field of ['totalPoints', 'availablePoints', 'tier', 'monthlyLoginDays']) {
      assert.notEqual(wallet[field], undefined, `${field} is needed by the summary paths`);
    }
  });
});

// ---------------------------------------------------------------------------

test('a projected save does not destroy history', async (t) => {
  await t.test('tracking a login leaves every transaction intact', async () => {
    // THE test. trackDailyLogin mutates and saves a wallet loaded without the
    // transactions path. If Mongoose wrote the whole document rather than the
    // modified paths, twelve transactions would silently become zero.
    const { user } = await walletWithHistory(12);

    const before = await raw(user._id);
    assert.equal(before.transactions.length, 12, 'precondition');

    const result = await trackDailyLogin(user._id);
    assert.equal(result.success, true, JSON.stringify(result));

    const after = await raw(user._id);
    assert.equal(after.transactions.length, 12, 'a projected save emptied the transaction array');
    assert.deepEqual(
      after.transactions.map((t2) => t2.description),
      before.transactions.map((t2) => t2.description),
      'the transactions changed identity, not just count'
    );
  });

  await t.test('it still records the login it was called for', async () => {
    const { user } = await walletWithHistory(3);
    await trackDailyLogin(user._id);

    const after = await raw(user._id);
    const today = new Date().toISOString().split('T')[0];
    assert.equal(after.lastLoginDate, today);
    assert.equal(after.monthlyLoginDays[today.substring(0, 7)], 1);
  });

  await t.test('tracking twice in a day is still a no-op', async () => {
    const { user } = await walletWithHistory(3);
    await trackDailyLogin(user._id);
    const second = await trackDailyLogin(user._id);

    assert.match(second.message, /already/i);
    assert.equal((await raw(user._id)).transactions.length, 3);
  });

  await t.test('points and tier survive the projected save', async () => {
    const { user } = await walletWithHistory(12);
    const before = await raw(user._id);

    await trackDailyLogin(user._id);

    const after = await raw(user._id);
    assert.equal(after.totalPoints, before.totalPoints);
    assert.equal(after.availablePoints, before.availablePoints);
    assert.equal(after.tier, before.tier);
  });
});

// ---------------------------------------------------------------------------

test('reads that display history still get it', async (t) => {
  await t.test('getWallet still returns recent transactions', async () => {
    // getWallet slices the ten most recent, so it cannot be projected. Pinned
    // so a future "optimisation" cannot quietly empty the dashboard.
    const { user } = await walletWithHistory(12);
    const view = await getWallet(user._id);

    assert.equal(view.recentTransactions.length, 10);
    assert.equal(view.totalPoints, 120);
    assert.equal(view.tier, 'bronze');
  });

  await t.test('the history endpoint still paginates real transactions', async () => {
    const { user } = await walletWithHistory(25);
    const page = await getTransactionHistory(user._id, 1, 10);

    assert.equal(page.transactions.length, 10);
    assert.equal(page.pagination.total, 25);
  });

  await t.test('awarding points still appends to the array', async () => {
    const { user } = await walletWithHistory(4);
    await awardPoints(user._id, 'report_property');

    const after = await raw(user._id);
    assert.ok(after.transactions.length > 4, 'the award path must still write history');
  });
});

// ---------------------------------------------------------------------------

test('response shapes and values are unchanged', async (t) => {
  await t.test('the wallet endpoint returns the same keys as before', async () => {
    const { user } = await walletWithHistory(6);
    const view = await getWallet(user._id);

    assert.deepEqual(
      Object.keys(view).sort(),
      ['availablePoints', 'nextTierProgress', 'recentTransactions', 'tier', 'tierMultiplier', 'totalPoints'].sort()
    );
  });

  await t.test('a login does not change any value the user can see', async () => {
    const { user } = await walletWithHistory(6);
    const before = await getWallet(user._id);

    await trackDailyLogin(user._id);

    const after = await getWallet(user._id);
    assert.equal(after.totalPoints, before.totalPoints);
    assert.equal(after.availablePoints, before.availablePoints);
    assert.equal(after.tier, before.tier);
    assert.equal(after.recentTransactions.length, before.recentTransactions.length);
  });
});

// ---------------------------------------------------------------------------

test('regression: the summary paths must not start hydrating again', async (t) => {
  const read = async (rel) => {
    const { readFileSync } = await import('node:fs');
    return readFileSync(new URL(rel, import.meta.url), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\r\n]*/g, '');
  };

  await t.test('trackDailyLogin asks for the projected wallet', async () => {
    const src = await read('../../services/rewardService.js');
    const fn = src.slice(src.indexOf('export const trackDailyLogin'));
    assert.match(
      fn.slice(0, 400), /withTransactions:\s*false/,
      'trackDailyLogin runs on every login; it must not load the array'
    );
  });

  await t.test('registration asks for the projected wallet', async () => {
    const src = await read('../../controllers/userController.js');
    const calls = [...src.matchAll(/getOrCreateWallet\([^)]*\)/g)].map((m) => m[0]);
    assert.ok(calls.length >= 2, `expected the two registration calls, found ${calls.length}`);
    assert.ok(
      calls.every((c) => /withTransactions:\s*false/.test(c)),
      `a registration call still hydrates transactions: ${calls.join(' | ')}`
    );
  });

  await t.test('the Hubble balance read is still projected', async () => {
    // Was already optimal before this phase. Pinned so it stays that way.
    const src = await read('../../controllers/hubbleController.js');
    assert.match(src, /\.select\("availablePoints"\)\.lean\(\)/);
  });
});
