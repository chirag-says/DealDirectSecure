/**
 * Stage 2 — money-path hardening for project bookings.
 *
 * Six changes, all on the path that takes real money over UPI:
 *
 *   1. CSRF on POST /api/bookings and /api/bookings/:id/payment. Both are
 *      cookie-authenticated and state-changing and were absent from the
 *      Phase-1 list, which already covers property edits, interest, campaign
 *      join and account deletion.
 *   2. Refuse a booking when availableUnits is undefined. The old check was
 *      `=== 0`, so a unit type whose inventory was never configured accepted
 *      enquiries and payments — and every verification then died on the
 *      $gte:1 decrement, auto-cancelling with "REFUND DUE".
 *   3. Refuse a booking when the token amount resolves to 0. Three of eight
 *      real unit types in dev have no bookingAmount; those produced "Pay
 *      exactly ₹0" and an admin verifying a zero payment.
 *   4. Surface UTR reuse at verification. One real transfer can be
 *      screenshotted into two bookings; the verifying admin saw nothing.
 *   5. AuditLog on verify and on status change. statusHistory lives on the
 *      document and dies with it; it cannot answer "what did admin X do".
 *   6. A user can cancel their own booking before it is confirmed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeUser, adminWithSession, asAdmin, seedTaxonomy, TEST_PASSWORD } from './setup/factories.js';

let api;
test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const backend = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');
const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

/** A builder → project → unit type chain. `inv`/`pay` override the defaults. */
async function makeChain({ inv = {}, pay = {} } = {}) {
  const builder = await M('Builder').create({
    name: 'Test Builder', phone: `9${Date.now().toString().slice(-9)}`, isActive: true,
  });
  const admin = await M('Admin').collection.insertOne({
    name: 'Seed', email: `seed-${Date.now()}-${Math.round(process.hrtime()[1])}@example.com`,
    createdAt: new Date(),
  });
  const project = await M('Project').create({
    builder: builder._id, createdBy: admin.insertedId,
    basics: { name: 'Test Project', category: 'Residential' },
    location: { city: 'Pune' },
  });
  const unitType = await M('UnitType').create({
    project: project._id, builder: builder._id, createdBy: admin.insertedId,
    config: { name: '2 BHK' },
    area: { carpetSqft: 900 },
    pricing: { basePrice: 5_000_000 },
    inventory: { totalUnits: 10, availableUnits: 10, bookedUnits: 0, blockedUnits: 0, ...inv },
    paymentTerms: { bookingAmount: 50_000, ...pay },
  });
  return { builder, project, unitType };
}

const ORIGIN = 'http://localhost:3000';

/**
 * Log in and carry a CSRF token.
 *
 * Booking creation, payment submission and cancellation are all on the CSRF
 * list now, so a fixture that only sends the session cookie gets a 403. That
 * 403 is the feature working; these helpers make the tests speak the same
 * protocol the real client does.
 */
async function loginUser() {
  const user = await makeUser({ role: 'user' });
  const res = await api.post('/api/users/login')
    .set('X-Forwarded-For', uniqueClientIp())
    .send({ email: user.email, password: TEST_PASSWORD });
  assert.equal(res.status, 200, `login failed: ${JSON.stringify(res.body).slice(0, 200)}`);

  const jar = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
  const token = decodeURIComponent(
    (jar.join('; ').match(/csrf_token=([^;]+)/) || [])[1] || ''
  );
  assert.ok(token, 'login issued no CSRF cookie');
  return { user, cookie: jar.join('; '), csrf: token };
}

/** POST with session cookie, matching CSRF header and a same-site Origin. */
const guarded = (path, { cookie, csrf }) =>
  api.post(path)
    .set('X-Forwarded-For', uniqueClientIp())
    .set('Cookie', cookie)
    .set('Origin', ORIGIN)
    .set('X-CSRF-Token', csrf);

const book = (session, body) => guarded('/api/bookings', session).send(body);

const validBody = (project, unitType) => ({
  projectId: String(project._id),
  unitTypeId: String(unitType._id),
  clientName: 'Test Buyer',
  clientPhone: '9876543210',
});

// ---------------------------------------------------------------------------
// 1. CSRF
// ---------------------------------------------------------------------------

test('booking endpoints are CSRF-guarded', async (t) => {
  await t.test('both routes are on the Phase-1 list', () => {
    const src = stripComments(backend('server.js'));
    assert.match(src, /app\.post\("\/api\/bookings",\s*csrfGuard\)/,
      'booking creation is not CSRF-guarded');
    assert.match(src, /app\.post\("\/api\/bookings\/:id\/payment",\s*csrfGuard\)/,
      'payment submission is not CSRF-guarded');
  });

  await t.test('the routes that were already guarded still are', () => {
    // Guards against a careless edit to the list.
    const src = stripComments(backend('server.js'));
    for (const route of [
      '/api/properties/add', '/api/properties/interested/:id',
      '/api/campaigns/:id/join', '/api/contact',
    ]) {
      assert.ok(src.includes(`"${route}", csrfGuard`), `${route} lost its guard`);
    }
  });
});

// ---------------------------------------------------------------------------
// 2 + 3. Booking-time guards
// ---------------------------------------------------------------------------

test('a booking cannot be created against unsellable inventory', async (t) => {
  await t.test('THE DEFECT: undefined availableUnits used to pass', async () => {
    // `=== 0` is false for undefined, so this reached payment and then died on
    // the $gte:1 decrement — money taken for stock that never existed.
    const { project, unitType } = await makeChain({
      inv: { totalUnits: undefined, availableUnits: undefined },
    });
    const session = await loginUser();

    const res = await book(session, validBody(project, unitType));
    assert.equal(res.status, 400, `expected refusal, got ${res.status}`);
    assert.match(JSON.stringify(res.body), /no units are available|NO_INVENTORY/i);
  });

  await t.test('zero availableUnits is still refused', async () => {
    const { project, unitType } = await makeChain({ inv: { availableUnits: 0 } });
    const session = await loginUser();
    assert.equal((await book(session, validBody(project, unitType))).status, 400);
  });

  await t.test('a configured unit type is still bookable', async () => {
    // The guard must not break the working path.
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const res = await book(session, validBody(project, unitType));
    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.data.tokenAmount, 50_000);
  });
});

test('a booking cannot be created with a zero token amount', async (t) => {
  await t.test('THE DEFECT: "Pay exactly ₹0" was reachable on real data', async () => {
    // 3 of 8 dev unit types have no bookingAmount and no project fallback.
    const { project, unitType } = await makeChain({ pay: { bookingAmount: undefined } });
    const session = await loginUser();

    const res = await book(session, validBody(project, unitType));
    assert.equal(res.status, 400, `expected refusal, got ${res.status}`);
    assert.match(JSON.stringify(res.body), /not configured|booking amount/i);
  });

  await t.test('the legacy project-level fallback still works', async () => {
    // Older projects carry financials.bookingAmount; that path must survive.
    const { project, unitType } = await makeChain({ pay: { bookingAmount: undefined } });
    await M('Project').updateOne(
      { _id: project._id }, { $set: { 'financials.bookingAmount': 25_000 } }
    );
    const session = await loginUser();

    const res = await book(session, validBody(project, unitType));
    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.data.tokenAmount, 25_000);
  });
});

// ---------------------------------------------------------------------------
// 6. Self-cancel
// ---------------------------------------------------------------------------

test('a user can cancel their own booking before it is confirmed', async (t) => {
  async function bookingFor(session, project, unitType) {
    const res = await book(session, validBody(project, unitType));
    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
    return res.body.data.bookingId;
  }
  const cancel = (session, id) =>
    guarded(`/api/bookings/${id}/cancel`, session).send({ reason: 'changed my mind' });

  await t.test('an enquiry can be cancelled', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const id = await bookingFor(session, project, unitType);

    const res = await cancel(session, id);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal((await M('ProjectBooking').findById(id)).status, 'cancelled');
  });

  await t.test('the cancellation is attributed to the user, not an admin', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const id = await bookingFor(session, project, unitType);
    await cancel(session, id);

    const doc = await M('ProjectBooking').findById(id).lean();
    const last = doc.statusHistory[doc.statusHistory.length - 1];
    assert.equal(last.status, 'cancelled');
    assert.equal(last.changedBy, 'user');
  });

  await t.test('a stranger cannot cancel someone else\'s booking', async () => {
    const { project, unitType } = await makeChain();
    const owner = await loginUser();
    const id = await bookingFor(owner, project, unitType);

    const other = await loginUser();
    const res = await cancel(other, id);
    assert.equal(res.status, 403, `IDOR: got ${res.status}`);
    assert.equal((await M('ProjectBooking').findById(id)).status, 'enquiry');
  });

  await t.test('a confirmed booking cannot be self-cancelled', async () => {
    // Inventory is held at that point; releasing it is an admin decision.
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const id = await bookingFor(session, project, unitType);
    await M('ProjectBooking').updateOne({ _id: id }, { $set: { status: 'confirmed' } });

    const res = await cancel(session, id);
    assert.equal(res.status, 400);
    assert.equal((await M('ProjectBooking').findById(id)).status, 'confirmed');
  });

  await t.test('payment evidence survives a cancellation', async () => {
    // The UTR and screenshot are the receipt. Cancelling must not erase them.
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const id = await bookingFor(session, project, unitType);
    await M('ProjectBooking').updateOne({ _id: id }, {
      $set: {
        status: 'payment_submitted',
        'payment.utrNumber': 'UTR123456',
        'payment.status': 'submitted',
      },
    });

    assert.equal((await cancel(session, id)).status, 200);
    const doc = await M('ProjectBooking').findById(id).lean();
    assert.equal(doc.status, 'cancelled');
    assert.equal(doc.payment.utrNumber, 'UTR123456', 'the payment reference was destroyed');
  });
});

// ---------------------------------------------------------------------------
// 4 + 5. Verification: UTR reuse and the audit trail
// ---------------------------------------------------------------------------

test('payment verification surfaces UTR reuse and is audited', async (t) => {
  await t.test('duplicate UTRs are reported to the verifying admin', async () => {
    const { project, unitType } = await makeChain();
    const ids = [];
    for (let i = 0; i < 2; i++) {
      const s2 = await loginUser();
      const r = await book(s2, validBody(project, unitType));
      assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 200));
      ids.push(r.body.data.bookingId);
    }
    await M('ProjectBooking').updateMany({ _id: { $in: ids } }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'SAME-UTR-9', 'payment.status': 'submitted' },
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/bookings/${ids[0]}/verify`), adminFixture)
      .send({ action: 'approve' });

    assert.equal(res.status, 409, `expected a duplicate refusal, got ${res.status}`);
    assert.match(JSON.stringify(res.body), /UTR|duplicate/i);
    assert.equal((await M('ProjectBooking').findById(ids[0])).status, 'payment_submitted',
      'the booking was confirmed despite the duplicate');
  });

  await t.test('an explicit override lets it through, and records why', async () => {
    const { project, unitType } = await makeChain();
    const ids = [];
    for (let i = 0; i < 2; i++) {
      const s2 = await loginUser();
      const r = await book(s2, validBody(project, unitType));
      assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 200));
      ids.push(r.body.data.bookingId);
    }
    await M('ProjectBooking').updateMany({ _id: { $in: ids } }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'SAME-UTR-9', 'payment.status': 'submitted' },
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/bookings/${ids[0]}/verify`), adminFixture)
      .send({ action: 'approve', adminNotes: 'bank re-used the ref, confirmed by phone', overrideDuplicateUtr: true });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal((await M('ProjectBooking').findById(ids[0])).status, 'confirmed');
  });

  await t.test('an override without a note is refused', async () => {
    // The note IS the audit trail for a deliberate duplicate approval.
    const { project, unitType } = await makeChain();
    const ids = [];
    for (let i = 0; i < 2; i++) {
      const s2 = await loginUser();
      const r = await book(s2, validBody(project, unitType));
      assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 200));
      ids.push(r.body.data.bookingId);
    }
    await M('ProjectBooking').updateMany({ _id: { $in: ids } }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'SAME-UTR-9', 'payment.status': 'submitted' },
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/bookings/${ids[0]}/verify`), adminFixture)
      .send({ action: 'approve', overrideDuplicateUtr: true });

    assert.equal(res.status, 400, `an unexplained override was accepted (${res.status})`);
  });

  await t.test('a unique UTR verifies without ceremony', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const r = await book(session, validBody(project, unitType));
    const id = r.body.data.bookingId;
    await M('ProjectBooking').updateOne({ _id: id }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'UNIQUE-1', 'payment.status': 'submitted' },
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/bookings/${id}/verify`), adminFixture)
      .send({ action: 'approve' });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal((await M('ProjectBooking').findById(id)).status, 'confirmed');
  });

  await t.test('cancelled bookings do not count as UTR collisions', async () => {
    // A rejected/cancelled attempt should not block a genuine re-submission.
    const { project, unitType } = await makeChain();
    const ids = [];
    for (let i = 0; i < 2; i++) {
      const s2 = await loginUser();
      const r = await book(s2, validBody(project, unitType));
      assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 200));
      ids.push(r.body.data.bookingId);
    }
    await M('ProjectBooking').updateOne({ _id: ids[1] }, {
      $set: { status: 'cancelled', 'payment.utrNumber': 'REUSED-OK' },
    });
    await M('ProjectBooking').updateOne({ _id: ids[0] }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'REUSED-OK', 'payment.status': 'submitted' },
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/bookings/${ids[0]}/verify`), adminFixture)
      .send({ action: 'approve' });

    assert.equal(res.status, 200, `a cancelled booking blocked a legitimate verification`);
  });

  await t.test('AUDIT: approving a payment writes an AuditLog entry', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const r = await book(session, validBody(project, unitType));
    const id = r.body.data.bookingId;
    await M('ProjectBooking').updateOne({ _id: id }, {
      $set: { status: 'payment_submitted', 'payment.utrNumber': 'AUDIT-1', 'payment.status': 'submitted' },
    });

    // Counted by CATEGORY, not in total. protectAdmin writes its own audit
    // entries on admin requests, so a bare countDocuments() rises whether or
    // not the booking action logged anything — which is exactly how the first
    // version of this test passed against a disabled audit call.
    const adminFixture = await adminWithSession(api);
    await asAdmin(api.put(`/api/bookings/${id}/verify`), adminFixture)
      .send({ action: 'approve' });

    const entry = await M('AuditLog').findOne({
      category: 'booking_management',
      action: 'booking_payment_verified',
      resourceId: String(id),
    }).lean() || await M('AuditLog').findOne({
      category: 'booking_management', action: 'booking_payment_verified',
    }).lean();

    assert.ok(entry, 'verifying a payment left no booking_management audit record');
    assert.equal(entry.metadata?.utrNumber, 'AUDIT-1', 'the UTR was not recorded');
  });

  await t.test('AUDIT: a status change writes one too', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const r = await book(session, validBody(project, unitType));
    const id = r.body.data.bookingId;

    const adminFixture = await adminWithSession(api);
    await asAdmin(api.put(`/api/bookings/${id}/status`), adminFixture)
      .send({ status: 'cancelled', adminNotes: 'buyer withdrew' });

    const entry = await M('AuditLog').findOne({
      category: 'booking_management', action: 'booking_status_changed',
    }).lean();

    assert.ok(entry, 'changing a booking status left no booking_management audit record');
    assert.equal(entry.metadata?.from, 'enquiry');
    assert.equal(entry.metadata?.to, 'cancelled');
  });
});

// ---------------------------------------------------------------------------
// The enquiry cap
// ---------------------------------------------------------------------------

test('booking creation is rate-limited by open enquiries', async (t) => {
  await t.test('a second open enquiry on the same unit type is refused', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();

    assert.equal((await book(session, validBody(project, unitType))).status, 201);
    const second = await book(session, validBody(project, unitType));
    assert.equal(second.status, 409, `duplicate enquiry allowed (${second.status})`);
  });

  await t.test('but cancelling frees the slot', async () => {
    const { project, unitType } = await makeChain();
    const session = await loginUser();
    const first = await book(session, validBody(project, unitType));

    await guarded(`/api/bookings/${first.body.data.bookingId}/cancel`, session).send({});

    assert.equal((await book(session, validBody(project, unitType))).status, 201,
      'a cancelled enquiry still blocks a new one');
  });
});
