/**
 * Phase 0: push tokens, the channel policy, the weekly cap, self-cleaning.
 *
 * Push goes to the loopback fake started by fakeProviders.js; a token whose
 * string contains "dead" is answered with DeviceNotRegistered so the disable
 * path is exercised without a device. Email is observed through the
 * "Would have sent email" console hook the older suites already use.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import {
  stopFakeProviders, pushBatchesSent, clearPushBatches,
  watchEmail, unwatchEmail, emailedAddresses, clearEmails, settleEmail,
} from './setup/fakeProviders.js';
import { makeUser, buyerWithSession, loginAs } from './setup/factories.js';

import { notifyUser, notifyUsers, pushOnly, WEEKLY_CAP } from '../../services/notificationService.js';
import { sendPush } from '../../services/pushService.js';

let api;
const M = (name) => mongoose.model(name);
const TOKEN_A = 'ExponentPushToken[aaaaaaaaaaaaaaaaaaaaaa]';
const TOKEN_B = 'ExponentPushToken[bbbbbbbbbbbbbbbbbbbbbb]';
const TOKEN_DEAD = 'ExponentPushToken[deaddeaddeaddeaddeadxx]';

const settle = (ms = 120) => new Promise((r) => setTimeout(r, ms));

test.before(async () => { api = await request(); watchEmail(); });
test.beforeEach(async () => { await truncateAll(); clearPushBatches(); clearEmails(); });
test.after(async () => { unwatchEmail(); await stopFakeProviders(); await stopTestDatabase(); });

// ---------------------------------------------------------------------------

test('device registration', async (t) => {
  await t.test('a valid token is stored against the session user', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    const res = await withClient(api.post('/api/users/push-token'), { cookies })
      .send({ token: TOKEN_A, platform: 'android', appVersion: '0.1.0', installationId: 'inst-1' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const doc = await M('PushToken').findOne({ token: TOKEN_A }).lean();
    assert.equal(String(doc.user), String(buyer._id));
    assert.equal(doc.platform, 'android');
    assert.equal(doc.disabledAt, null);
  });

  await t.test('a malformed token or platform is refused with a code', async () => {
    const { cookies } = await buyerWithSession(api);
    const bad = await withClient(api.post('/api/users/push-token'), { cookies }).send({ token: 'abc', platform: 'android' });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, 'INVALID_PUSH_TOKEN');
    const badPlatform = await withClient(api.post('/api/users/push-token'), { cookies }).send({ token: TOKEN_A, platform: 'web' });
    assert.equal(badPlatform.status, 400);
    assert.equal(badPlatform.body.code, 'INVALID_PLATFORM');
  });

  await t.test('registration requires a session', async () => {
    const res = await withClient(api.post('/api/users/push-token')).send({ token: TOKEN_A, platform: 'ios' });
    assert.equal(res.status, 401);
  });

  await t.test('the same token registered by a second account moves to that account', async () => {
    const first = await buyerWithSession(api);
    const second = await buyerWithSession(api);
    await withClient(api.post('/api/users/push-token'), { cookies: first.cookies }).send({ token: TOKEN_A, platform: 'ios' });
    await withClient(api.post('/api/users/push-token'), { cookies: second.cookies }).send({ token: TOKEN_A, platform: 'ios' });
    const docs = await M('PushToken').find({ token: TOKEN_A }).lean();
    assert.equal(docs.length, 1, 'one row per token');
    assert.equal(String(docs[0].user), String(second.buyer._id));
  });

  await t.test('re-registering a disabled token re-enables it', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    await M('PushToken').create({ user: buyer._id, token: TOKEN_A, platform: 'ios', disabledAt: new Date() });
    await withClient(api.post('/api/users/push-token'), { cookies }).send({ token: TOKEN_A, platform: 'ios' });
    const doc = await M('PushToken').findOne({ token: TOKEN_A }).lean();
    assert.equal(doc.disabledAt, null);
  });

  await t.test('only the owning account can remove a token', async () => {
    const first = await buyerWithSession(api);
    const second = await buyerWithSession(api);
    await withClient(api.post('/api/users/push-token'), { cookies: first.cookies }).send({ token: TOKEN_A, platform: 'ios' });
    const other = await withClient(api.delete('/api/users/push-token'), { cookies: second.cookies }).send({ token: TOKEN_A });
    assert.equal(other.status, 200);
    assert.equal(other.body.removed, false);
    assert.equal(await M('PushToken').countDocuments({ token: TOKEN_A }), 1);
    const own = await withClient(api.delete('/api/users/push-token'), { cookies: first.cookies }).send({ token: TOKEN_A });
    assert.equal(own.body.removed, true);
    assert.equal(await M('PushToken').countDocuments({ token: TOKEN_A }), 0);
  });

  await t.test('logout removes the token the device hands over, and nothing else', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    await M('PushToken').create({ user: buyer._id, token: TOKEN_A, platform: 'ios' });
    await M('PushToken').create({ user: buyer._id, token: TOKEN_B, platform: 'android' });
    const res = await withClient(api.post('/api/users/logout'), { cookies }).send({ pushToken: TOKEN_A });
    assert.equal(res.status, 200);
    const left = await M('PushToken').find({ user: buyer._id }).lean();
    assert.deepEqual(left.map((d) => d.token), [TOKEN_B]);
  });

  await t.test('logout-all removes every device of the account', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    await M('PushToken').create({ user: buyer._id, token: TOKEN_A, platform: 'ios' });
    await M('PushToken').create({ user: buyer._id, token: TOKEN_B, platform: 'android' });
    const res = await withClient(api.post('/api/users/logout-all'), { cookies }).send({});
    assert.equal(res.status, 200);
    assert.equal(await M('PushToken').countDocuments({ user: buyer._id }), 0);
  });

  await t.test('account deletion takes the tokens with it', async () => {
    const buyer = await makeUser({ role: 'buyer' });
    const cookies = await loginAs(api, buyer);
    await M('PushToken').create({ user: buyer._id, token: TOKEN_A, platform: 'ios' });
    const { TEST_PASSWORD } = await import('./setup/factories.js');
    const res = await withClient(api.delete('/api/users/me'), { cookies }).send({ password: TEST_PASSWORD, confirmation: 'DELETE' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await M('PushToken').countDocuments({ user: buyer._id }), 0);
  });
});

// ---------------------------------------------------------------------------

test('push delivery', async (t) => {
  await t.test('a notification reaches every enabled device with routable data', async () => {
    const user = await makeUser();
    await M('PushToken').create({ user: user._id, token: TOKEN_A, platform: 'ios' });
    await M('PushToken').create({ user: user._id, token: TOKEN_B, platform: 'android' });
    await M('PushToken').create({ user: user._id, token: 'ExponentPushToken[cccccccccccccccccccccc]', platform: 'android', disabledAt: new Date() });

    const propertyId = new mongoose.Types.ObjectId();
    const doc = await notifyUser(user._id, {
      title: 'Hello', message: 'World', type: 'saved-search-match',
      data: { propertyId, savedSearchId: new mongoose.Types.ObjectId(), secret: 'never-sent' },
    });
    await settle();

    const batches = pushBatchesSent();
    assert.equal(batches.length, 1);
    const msgs = batches[0];
    assert.equal(msgs.length, 2, 'the disabled device is skipped');
    assert.deepEqual(msgs.map((m) => m.to).sort(), [TOKEN_A, TOKEN_B].sort());
    for (const m of msgs) {
      assert.equal(m.title, 'Hello');
      assert.equal(m.data.kind, 'property');
      assert.equal(m.data.propertyId, String(propertyId));
      assert.equal(m.data.notificationId, String(doc._id));
      assert.equal(m.data.secret, undefined, 'only routable ids travel in the push');
    }
  });

  await t.test('the persisted row carries data.kind from the policy', async () => {
    const user = await makeUser();
    const doc = await notifyUser(user._id, { title: 'x', message: 'y', type: 'deal_reward', data: { verificationId: new mongoose.Types.ObjectId() } });
    const stored = await M('Notification').findById(doc._id).lean();
    assert.equal(stored.data.kind, 'dealReward');
    const custom = await notifyUser(user._id, { title: 'x', message: 'y', type: 'deal_reward', data: { kind: 'custom' } });
    assert.equal((await M('Notification').findById(custom._id).lean()).data.kind, 'custom', 'an explicit kind is respected');
  });

  await t.test('a token Expo reports as unregistered is disabled', async () => {
    const user = await makeUser();
    await M('PushToken').create({ user: user._id, token: TOKEN_DEAD, platform: 'android' });
    const result = await sendPush([{ userId: user._id, title: 't', body: 'b' }]);
    assert.equal(result.disabled, 1);
    const doc = await M('PushToken').findOne({ token: TOKEN_DEAD }).lean();
    assert.ok(doc.disabledAt instanceof Date);
  });

  await t.test('a user with no device produces no batch, and no error', async () => {
    const user = await makeUser();
    await notifyUser(user._id, { title: 'x', message: 'y', type: 'general' });
    await settle();
    assert.equal(pushBatchesSent().length, 0);
  });

  await t.test('a batch fans out to many users in one post', async () => {
    const users = await Promise.all([makeUser(), makeUser(), makeUser()]);
    for (const [i, u] of users.entries()) {
      await M('PushToken').create({ user: u._id, token: `ExponentPushToken[user${i}user${i}user${i}user${i}xx]`, platform: 'ios' });
    }
    await notifyUsers(users.map((u) => ({ user: u._id, title: 'a', message: 'b', type: 'general' })));
    await settle();
    assert.equal(pushBatchesSent().length, 1);
    assert.equal(pushBatchesSent()[0].length, 3);
  });

  await t.test('pushOnly writes no notification row and throttles per key', async () => {
    const user = await makeUser();
    await M('PushToken').create({ user: user._id, token: TOKEN_A, platform: 'ios' });
    const first = await pushOnly(user._id, { title: 't', body: 'b', data: { kind: 'message' }, throttleKey: 'conv:1' });
    const second = await pushOnly(user._id, { title: 't', body: 'b', data: { kind: 'message' }, throttleKey: 'conv:1' });
    assert.equal(first.sent, 1);
    assert.equal(second.throttled, true);
    assert.equal(await M('Notification').countDocuments({ user: user._id }), 0);
  });
});

// ---------------------------------------------------------------------------

test('channel policy and the weekly cap', async (t) => {
  await t.test('an "always" type emails as before, every time', async () => {
    const user = await makeUser();
    for (let i = 0; i < WEEKLY_CAP + 2; i += 1) {
      await notifyUser(user._id, { title: 'x', message: 'y', type: 'general' });
    }
    await settleEmail();
    assert.equal(emailedAddresses().filter((a) => a === user.email).length, WEEKLY_CAP + 2);
  });

  await t.test('a "capped" type stops emailing at the weekly cap', async () => {
    const user = await makeUser();
    for (let i = 0; i < WEEKLY_CAP + 3; i += 1) {
      await notifyUser(user._id, { title: 'x', message: 'y', type: 'review_request' });
      await settleEmail(80);
    }
    assert.equal(emailedAddresses().filter((a) => a === user.email).length, WEEKLY_CAP);
    assert.equal(await M('OutboundLog').countDocuments({ user: user._id, channel: 'email' }), WEEKLY_CAP);
    // The in-app rows are all there regardless of the cap.
    assert.equal(await M('Notification').countDocuments({ user: user._id }), WEEKLY_CAP + 3);
  });

  await t.test('a "never" type writes the row and sends no email', async () => {
    const user = await makeUser();
    await notifyUser(user._id, { title: 'x', message: 'y', type: 'deal_stage' });
    await settleEmail();
    assert.equal(emailedAddresses().filter((a) => a === user.email).length, 0);
    assert.equal(await M('Notification').countDocuments({ user: user._id }), 1);
  });

  await t.test('the email preference is still honoured for every mode', async () => {
    const user = await makeUser({ preferences: { emailNotifications: false } });
    await notifyUser(user._id, { title: 'x', message: 'y', type: 'general' });
    await notifyUser(user._id, { title: 'x', message: 'y', type: 'review_request' });
    await settleEmail();
    assert.equal(emailedAddresses().filter((a) => a === user.email).length, 0);
  });

  await t.test('a recipient that no longer exists is skipped without failing the batch', async () => {
    const ghost = new mongoose.Types.ObjectId();
    const user = await makeUser();
    const docs = await notifyUsers([
      { user: ghost, title: 'x', message: 'y', type: 'general' },
      { user: user._id, title: 'x', message: 'y', type: 'general' },
    ]);
    assert.equal(docs.length, 2);
    await settleEmail();
    assert.equal(emailedAddresses().filter((a) => a === user.email).length, 1);
  });
});

// ---------------------------------------------------------------------------

test('self-cleaning', async (t) => {
  await t.test('read notifications carry a partial TTL index; unread ones never expire', async () => {
    const indexes = await M('Notification').collection.indexes();
    const ttl = indexes.find((i) => i.name === 'ttl_read_notifications');
    assert.ok(ttl, 'the TTL index exists');
    assert.equal(ttl.expireAfterSeconds, 90 * 24 * 3600);
    assert.deepEqual(ttl.partialFilterExpression, { isRead: true });
  });

  await t.test('the outbound log expires on its own', async () => {
    const indexes = await M('OutboundLog').collection.indexes();
    assert.ok(indexes.some((i) => i.expireAfterSeconds === 8 * 24 * 3600));
  });
});
