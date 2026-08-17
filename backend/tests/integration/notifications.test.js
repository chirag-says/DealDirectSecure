/**
 * Suite 4: Notification read endpoints.
 *
 * Covers the fix for the route-ordering defect that made
 * `PATCH /api/notifications/mark-all/read` unreachable: `/:id/read` was
 * declared first, so Express matched the wildcard, `markNotificationRead`
 * received `id = "mark-all"`, the ObjectId cast failed and it returned 500.
 * Mark-all-as-read had never worked. Both handlers were already correct.
 *
 * The email assertions are the reason this is a separate suite rather than two
 * more cases in authorization.test.js. Notifications email from a `post("save")`
 * hook, and marking one read IS a save, so "mark read" and "send email" are one
 * keystroke apart in this model. A Phase 1 fix made the hook fire only for
 * inserts; nothing until now proved that from the outside, and the two read
 * paths reach the database by different routes (`save()` versus `updateMany`),
 * so they can regress independently.
 *
 * The first test is a control. Without it, every "no email was sent" assertion
 * below would also pass if the observer were simply broken.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import {
  watchEmail, unwatchEmail, emailedAddresses, clearEmails, settleEmail,
  stopFakeProviders,
} from './setup/fakeProviders.js';
import { makeUser, makeNotification, loginAs } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); watchEmail(); });
test.beforeEach(async () => { await truncateAll(); clearEmails(); });
test.after(async () => { unwatchEmail(); await stopFakeProviders(); await stopTestDatabase(); });

const Notification = () => mongoose.model('Notification');

const as = (cookies) => ({
  get: (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
  patch: (p) => api.patch(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
});

// ---------------------------------------------------------------------------

test('email observation control', async (t) => {
  await t.test('creating a notification does attempt an email', async () => {
    // If this fails, every "sent no email" assertion in this file is vacuous.
    const user = await makeUser();
    await makeNotification(user, { title: 'Control' });
    await settleEmail();

    assert.deepEqual(
      emailedAddresses(), [user.email],
      'a newly created notification should email its owner exactly once'
    );
  });
});

// ---------------------------------------------------------------------------

test('mark all notifications read', async (t) => {
  await t.test('succeeds and is reachable at all', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    await makeNotification(user);

    const res = await as(cookies).patch('/api/notifications/mark-all/read');
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.success, true);
  });

  await t.test('marks every unread notification the caller owns', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const own = await Promise.all([
      makeNotification(user, { title: 'One' }),
      makeNotification(user, { title: 'Two' }),
      makeNotification(user, { title: 'Three' }),
    ]);

    const res = await as(cookies).patch('/api/notifications/mark-all/read');
    assert.equal(res.status, 200);

    const stored = await Notification().find({ _id: { $in: own.map((n) => n._id) } }).lean();
    assert.equal(stored.length, 3);
    assert.deepEqual(
      stored.map((n) => n.isRead), [true, true, true],
      'all three of the caller\'s notifications should be read'
    );
  });

  await t.test('leaves an already-read notification alone and stays idempotent', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const already = await makeNotification(user, { isRead: true });

    const first = await as(cookies).patch('/api/notifications/mark-all/read');
    const second = await as(cookies).patch('/api/notifications/mark-all/read');

    assert.equal(first.status, 200);
    assert.equal(second.status, 200, 'calling it twice must not fail');

    const stored = await Notification().findById(already._id).lean();
    assert.equal(stored.isRead, true);
  });

  await t.test('does not touch another user\'s notifications', async () => {
    const [a, b] = [await makeUser(), await makeUser()];
    const cookiesA = await loginAs(api, a);
    const mine = await makeNotification(a);
    const theirs = await makeNotification(b);

    const res = await as(cookiesA).patch('/api/notifications/mark-all/read');
    assert.equal(res.status, 200);

    assert.equal((await Notification().findById(mine._id).lean()).isRead, true);
    assert.notEqual(
      (await Notification().findById(theirs._id).lean()).isRead, true,
      'another user\'s notification must stay unread'
    );
  });

  await t.test('sends no email', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    await makeNotification(user);
    await makeNotification(user);
    await settleEmail();

    // Two creations, therefore two emails. Everything after this point must add
    // none: the user is reading messages, not receiving new ones.
    assert.equal(emailedAddresses().length, 2, 'precondition: creation emails');
    clearEmails();

    const res = await as(cookies).patch('/api/notifications/mark-all/read');
    assert.equal(res.status, 200);
    await settleEmail();

    assert.deepEqual(
      emailedAddresses(), [],
      'marking notifications read must not re-send their emails'
    );
  });

  await t.test('requires a session', async () => {
    const res = await api
      .patch('/api/notifications/mark-all/read')
      .set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 401);
  });
});

// ---------------------------------------------------------------------------

test('mark a single notification read, unchanged by the route reorder', async (t) => {
  await t.test('still marks the caller\'s own notification read', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const own = await makeNotification(user);

    const res = await as(cookies).patch(`/api/notifications/${own._id}/read`);
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const stored = await Notification().findById(own._id).lean();
    assert.equal(stored.isRead, true);
  });

  await t.test('marks only the one named, not the rest', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const target = await makeNotification(user, { title: 'Target' });
    const other = await makeNotification(user, { title: 'Other' });

    await as(cookies).patch(`/api/notifications/${target._id}/read`);

    assert.equal((await Notification().findById(target._id).lean()).isRead, true);
    assert.notEqual(
      (await Notification().findById(other._id).lean()).isRead, true,
      'the single-read endpoint must not behave like mark-all'
    );
  });

  await t.test('sends no email, because the save is an update and not an insert', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const own = await makeNotification(user);
    await settleEmail();
    assert.equal(emailedAddresses().length, 1, 'precondition: the creation email');
    clearEmails();

    // This path calls `notification.save()`, so the post-save hook DOES run.
    // It returns early only because $locals.wasNew is false. That is the
    // invariant being pinned: one notification, one email, however many times
    // it is read.
    await as(cookies).patch(`/api/notifications/${own._id}/read`);
    await settleEmail();

    assert.deepEqual(emailedAddresses(), [], 'reading a notification must not re-send it');
  });

  await t.test('404s on another user\'s notification and leaves it unread', async () => {
    const [a, b] = [await makeUser(), await makeUser()];
    const cookiesA = await loginAs(api, a);
    const theirs = await makeNotification(b);

    const res = await as(cookiesA).patch(`/api/notifications/${theirs._id}/read`);
    assert.equal(res.status, 404);

    assert.notEqual((await Notification().findById(theirs._id).lean()).isRead, true);
  });

  await t.test('404s on an id that does not exist', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);

    const res = await as(cookies).patch(`/api/notifications/${new mongoose.Types.ObjectId()}/read`);
    assert.equal(res.status, 404);
  });

  await t.test('does not accept "mark-all" as a notification id', async () => {
    // The inverse of the original defect. Before the reorder this path reached
    // markNotificationRead; it must now reach the literal route instead, and
    // must never be treated as an identifier.
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const own = await makeNotification(user, { isRead: false });

    const res = await as(cookies).patch('/api/notifications/mark-all/read');
    assert.equal(res.status, 200);
    assert.notEqual(res.status, 500, 'the ObjectId cast must not be reached');

    assert.equal((await Notification().findById(own._id).lean()).isRead, true);
  });

  await t.test('requires a session', async () => {
    const user = await makeUser();
    const own = await makeNotification(user);

    const res = await api
      .patch(`/api/notifications/${own._id}/read`)
      .set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 401);
  });
});
