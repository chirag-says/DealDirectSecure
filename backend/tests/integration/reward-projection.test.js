/**
 * Reward wallet projection.
 *
 * `getOrCreateWallet(userId, { withTransactions: false })` loads a wallet
 * WITHOUT its embedded transaction array, for the paths that only need points
 * and tier (registration and OTP verification create the wallet this way).
 * The invariant under test: saving a document loaded through that projection
 * must write only the modified paths. If Mongoose ever wrote the whole
 * document, a projected save would silently replace a twelve-entry history
 * with an empty array.
 *
 * The original mutator exercised here was `trackDailyLogin`. Phase 0 removed
 * the login-streak mechanic (F1), so the projected save is now driven through
 * `lastTierReviewAt`, a field the summary paths still own. The invariant is
 * unchanged; only the field that carries it changed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeUser } from './setup/factories.js';

import {
  getOrCreateWallet, getWallet, awardPoints, getTransactionHistory,
} from '../../services/rewardService.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Reward = () => mongoose.model('Reward');

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

/** The projected mutation: load without the array, touch one field, save. */
async function projectedTouch(userId, at = new Date()) {
  const wallet = await getOrCreateWallet(userId, { withTransactions: false });
  wallet.lastTierReviewAt = at;
  await wallet.save();
}

// ---------------------------------------------------------------------------

test('the summary paths no longer hydrate the array', async (t) => {
  await t.test('a projected load carries no transactions', async () => {
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

  await t.test('a summary load still carries points and tier', async () => {
    const { user } = await walletWithHistory(5);
    const wallet = await getOrCreateWallet(user._id, { withTransactions: false });

    for (const field of ['totalPoints', 'availablePoints', 'tier']) {
      assert.notEqual(wallet[field], undefined, `${field} is needed by the summary paths`);
    }
  });

  await t.test('the streak fields are gone from the schema (Phase 0, F1)', async () => {
    const paths = Object.keys(Reward().schema.paths);
    assert.ok(!paths.includes('monthlyLoginDays'), 'monthlyLoginDays came back');
    assert.ok(!paths.includes('lastLoginDate'), 'lastLoginDate came back');
  });
});

// ---------------------------------------------------------------------------

test('a projected save does not destroy history', async (t) => {
  await t.test('a projected save leaves every transaction intact', async () => {
    // THE test. The mutator saves a wallet loaded without the transactions
    // path. If Mongoose wrote the whole document rather than the modified
    // paths, twelve transactions would silently become zero.
    const { user } = await walletWithHistory(12);

    const before = await raw(user._id);
    assert.equal(before.transactions.length, 12, 'precondition');

    await projectedTouch(user._id);

    const after = await raw(user._id);
    assert.equal(after.transactions.length, 12, 'a projected save emptied the transaction array');
    assert.deepEqual(
      after.transactions.map((t2) => t2.description),
      before.transactions.map((t2) => t2.description),
      'the transactions changed identity, not just count'
    );
  });

  await t.test('it still records the field it was called for', async () => {
    const { user } = await walletWithHistory(3);
    const at = new Date('2026-09-04T10:00:00.000Z');
    await projectedTouch(user._id, at);

    const after = await raw(user._id);
    assert.equal(new Date(after.lastTierReviewAt).toISOString(), at.toISOString());
    assert.equal(after.transactions.length, 3);
  });

  await t.test('points and tier survive the projected save', async () => {
    const { user } = await walletWithHistory(12);
    const before = await raw(user._id);

    await projectedTouch(user._id);

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
