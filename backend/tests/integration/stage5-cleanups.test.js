/**
 * Stage 5 — media lifecycle, dark-feature flags, and the seven cleanups.
 *
 * MEDIA. Images were append-only with no delete or reorder, and every removal
 * or replacement leaked the Cloudinary asset forever — payment screenshots
 * included. Property deletion already does this properly (propertyAssets.js);
 * projects and unit types never did.
 *
 * CHAT. A full Socket.IO server, seven routes and an admin moderation page for
 * a widget no page mounts. Flagged off rather than deleted: mobile has chat
 * screens built, and the code is fine — it is the mounting that is wrong.
 *
 * SITE VISITS. Three unconnected fragments — a modal that fabricates success
 * with setTimeout, chat messages typed 'visit_request', and an admin page that
 * shows the first 20 property leads filtered client-side. No visit entity
 * exists anywhere. Deleted, folded into the lead pipeline.
 *
 * CLEANUPS. Seven small verified fixes, each with its own reason.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync, existsSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  makeUser, makeOwner, makeProperty, adminWithSession, asAdmin,
  seedTaxonomy, TEST_PASSWORD,
} from './setup/factories.js';

let api;
test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const repo = (rel) => new URL(`../../../${rel}`, import.meta.url);
const readRepo = (rel) => readFileSync(repo(rel), 'utf8');
const backend = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');
const strip = (s) =>
  s.replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, '')
   .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

// ---------------------------------------------------------------------------
// Media lifecycle
// ---------------------------------------------------------------------------

test('project media can be removed, and removal destroys the asset', async (t) => {
  async function projectWithImages() {
    const builder = await M('Builder').create({
      name: 'B', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
    });
    const admin = await M('Admin').collection.insertOne({
      name: 'S', email: `s-${Date.now()}-${process.hrtime()[1]}@example.com`, createdAt: new Date(),
    });
    return M('Project').create({
      builder: builder._id, createdBy: admin.insertedId,
      basics: { name: 'P', category: 'Residential' }, location: { city: 'Pune' },
      media: {
        exteriorImages: [
          'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/a.jpg',
          'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg',
          'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/c.jpg',
        ],
      },
    });
  }

  await t.test('an image can be removed from a field', async () => {
    const project = await projectWithImages();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.delete(`/api/projects/${project._id}/media/exteriorImages`), admin)
      .send({ urls: ['https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg'] });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));

    const fresh = await M('Project').findById(project._id).lean();
    assert.equal(fresh.media.exteriorImages.length, 2);
    assert.ok(!fresh.media.exteriorImages.some((u) => u.endsWith('b.jpg')));
  });

  await t.test('the remaining images keep their order', async () => {
    // Order is the gallery order and the first is the listing hero, so a
    // removal that shuffles the rest silently changes the card everywhere.
    const project = await projectWithImages();
    const admin = await adminWithSession(api);
    await asAdmin(api.delete(`/api/projects/${project._id}/media/exteriorImages`), admin)
      .send({ urls: ['https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg'] });

    const fresh = await M('Project').findById(project._id).lean();
    assert.ok(fresh.media.exteriorImages[0].endsWith('a.jpg'));
    assert.ok(fresh.media.exteriorImages[1].endsWith('c.jpg'));
  });

  await t.test('images can be reordered — the first one is the listing hero', async () => {
    const project = await projectWithImages();
    const admin = await adminWithSession(api);
    const reversed = [
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/c.jpg',
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg',
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/a.jpg',
    ];

    const res = await asAdmin(api.put(`/api/projects/${project._id}/media/exteriorImages/order`), admin)
      .send({ urls: reversed });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.deepEqual((await M('Project').findById(project._id).lean()).media.exteriorImages, reversed);
  });

  await t.test('a reorder cannot smuggle in or drop an image', async () => {
    // Otherwise "reorder" becomes an unaudited replace.
    const project = await projectWithImages();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.put(`/api/projects/${project._id}/media/exteriorImages/order`), admin)
      .send({ urls: ['https://res.cloudinary.com/dd/image/upload/v1/evil.jpg'] });
    assert.equal(res.status, 400, `a reorder replaced the set (${res.status})`);
    assert.equal((await M('Project').findById(project._id).lean()).media.exteriorImages.length, 3);
  });

  await t.test('an unknown media field is refused', async () => {
    const project = await projectWithImages();
    const admin = await adminWithSession(api);
    const res = await asAdmin(api.delete(`/api/projects/${project._id}/media/somethingElse`), admin)
      .send({ urls: ['x'] });
    assert.equal(res.status, 400);
  });

  await t.test('removal actually calls destroy — observed, not read', async () => {
    // Nothing ever destroyed a replaced or removed asset. Cost aside, payment
    // screenshots live in the same Cloudinary account, so an orphan is a
    // payment record with no document pointing at it.
    //
    // Spied rather than source-matched: mutation testing showed that "the file
    // mentions destroyAssets" survives replacing the call with Promise.resolve.
    const { cloudinary } = await import('../../middleware/upload.js');
    const original = cloudinary.uploader.destroy;
    const destroyed = [];
    cloudinary.uploader.destroy = async (publicId) => { destroyed.push(publicId); return { result: 'ok' }; };

    try {
      const project = await projectWithImages();
      const admin = await adminWithSession(api);
      await asAdmin(api.delete(`/api/projects/${project._id}/media/exteriorImages`), admin)
        .send({ urls: ['https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg'] });

      assert.deepEqual(destroyed, ['dealdirect/projects/b'],
        `the asset was not destroyed (destroy calls: ${JSON.stringify(destroyed)})`);
    } finally {
      cloudinary.uploader.destroy = original;
    }
  });

  await t.test('a reorder cannot repeat one image to drop another', async () => {
    // Same length, same membership, different multiset — a naive "same set"
    // check passes and one image silently disappears.
    const project = await projectWithImages();
    const admin = await adminWithSession(api);
    const dup = [
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/a.jpg',
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/a.jpg',
      'https://res.cloudinary.com/dd/image/upload/v1/dealdirect/projects/b.jpg',
    ];

    const res = await asAdmin(api.put(`/api/projects/${project._id}/media/exteriorImages/order`), admin)
      .send({ urls: dup });
    assert.equal(res.status, 400, `a duplicate reorder was accepted (${res.status})`);
    assert.equal((await M('Project').findById(project._id).lean()).media.exteriorImages.length, 3);
  });

  await t.test('and there is a shared helper rather than four copies', () => {
    assert.ok(existsSync(new URL('../../utils/cloudinaryAssets.js', import.meta.url)),
      'no shared asset-destroy helper');
  });
});

// ---------------------------------------------------------------------------
// Chat behind a flag
// ---------------------------------------------------------------------------

test('the dark chat stack is behind a flag', async (t) => {
  await t.test('the socket server is conditional', () => {
    const src = strip(backend('server.js'));
    assert.match(src, /CHAT_ENABLED/, 'the Socket.IO server still boots unconditionally');
  });

  await t.test('the chat routes are conditional too', () => {
    // Anchored to the MOUNT. The first '/api/chat' in server.js belongs to the
    // CSRF list, so a positional search finds the wrong line entirely.
    const src = strip(backend('server.js'));
    assert.ok(src.includes('if (CHAT_ENABLED) app.use("/api/chat", chatRoutes);'),
      'the chat routes mount regardless of the flag');
  });

  await t.test('nothing was deleted — the code is fine, the mounting was wrong', () => {
    for (const rel of [
      'backend/controllers/chatController.js',
      'backend/routes/chatRoutes.js',
      'backend/models/Conversation.js',
      'backend/models/Message.js',
      'client-next/src/components/Chat/ChatWidget.jsx',
      'Admin/src/pages/ReportedMessages.jsx',
    ]) {
      assert.ok(existsSync(repo(rel)), `${rel} was deleted — flag it, do not remove it`);
    }
  });

  await t.test('chat is off by default', async () => {
    // The whole point: zero users today, so the surface should not be live.
    const res = await api.get('/api/chat/conversations').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404, `chat is still mounted (${res.status})`);
  });
});

// ---------------------------------------------------------------------------
// Site visits: three fragments, no feature
// ---------------------------------------------------------------------------

test('the site-visit fiction is gone', async (t) => {
  await t.test('the admin page is deleted', () => {
    assert.equal(existsSync(repo('Admin/src/pages/SiteVisitManagement.jsx')), false,
      'the page that showed the first 20 leads and called them site visits is back');
  });

  await t.test('and unrouted', () => {
    const app = strip(readRepo('Admin/src/App.jsx'));
    assert.doesNotMatch(app, /SiteVisitManagement/);
    assert.doesNotMatch(app, /site-visits/);
  });

  await t.test('the modal no longer fabricates success', () => {
    // It waited 1500ms and claimed "Visit scheduled successfully!" with no API
    // call behind it.
    if (!existsSync(repo('client-next/src/components/VisitModal/VisitModal.jsx'))) return;
    const src = strip(readRepo('client-next/src/components/VisitModal/VisitModal.jsx'));
    assert.doesNotMatch(src, /setTimeout/, 'the fake-success path survives');
    assert.doesNotMatch(src, /Check your email for details/);
  });

  await t.test('lead statuses still exist — visits fold into the pipeline', () => {
    // Not a deletion of the concept, a relocation of it.
    const lead = backend('models/Lead.js');
    assert.match(lead, /interested/);
    assert.match(lead, /negotiating/);
  });
});

// ---------------------------------------------------------------------------
// The seven cleanups
// ---------------------------------------------------------------------------

test('cleanup: the interest cap ignores dead listings', async (t) => {
  await t.test('a sold property does not consume an interest slot', async () => {
    // The cap is 5. A user whose five interests all sold was locked out until
    // they manually un-saved, which nothing told them to do.
    const buyer = await makeUser({ role: 'user' });
    const owner = await makeOwner();

    const props = [];
    for (let i = 0; i < 5; i++) {
      const p = await makeProperty(owner, { isApproved: true });
      await M('Property').updateOne({ _id: p._id }, {
        $push: { interestedUsers: { user: buyer._id, interestedAt: new Date() } },
        $set: { status: 'sold' },
      });
      props.push(p);
    }

    const fresh = await makeProperty(owner, { isApproved: true });
    const res = await api.post('/api/users/login')
      .set('X-Forwarded-For', uniqueClientIp())
      .send({ email: buyer.email, password: TEST_PASSWORD });
    const jar = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
    const csrf = decodeURIComponent((jar.join('; ').match(/csrf_token=([^;]+)/) || [])[1] || '');

    const interest = await api.post(`/api/properties/interested/${fresh._id}`)
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', jar.join('; '))
      .set('Origin', 'http://localhost:3000').set('X-CSRF-Token', csrf).send({});

    assert.equal(interest.status, 200,
      `five SOLD properties still block a new interest: ${JSON.stringify(interest.body).slice(0, 150)}`);
  });
});

test('cleanup: a campaign with paid members cannot be quietly cancelled', async (t) => {
  await t.test('cancelling is refused while paid members are unhandled', async () => {
    const builder = await M('Builder').create({
      name: 'B', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
    });
    const admin = await M('Admin').collection.insertOne({
      name: 'S', email: `s-${Date.now()}-${process.hrtime()[1]}@example.com`, createdAt: new Date(),
    });
    const project = await M('Project').create({
      builder: builder._id, createdBy: admin.insertedId,
      basics: { name: 'P' }, location: { city: 'Pune' },
    });
    const unitType = await M('UnitType').create({
      project: project._id, builder: builder._id, createdBy: admin.insertedId,
      config: { name: '2 BHK' },
    });
    const campaign = await M('GroupBuyCampaign').create({
      unitType: unitType._id, project: project._id, builder: builder._id,
      createdBy: admin.insertedId,
      basics: { name: 'C' }, buyerTargets: { minBuyers: 2 },
      duration: { startDate: new Date(), endDate: new Date(Date.now() + 86400000) },
      discountPerBuyer: 100000, status: 'active',
    });
    const user = await makeUser({ role: 'user' });
    await M('CampaignMember').create({
      campaign: campaign._id, user: user._id, status: 'active', tokenStatus: 'paid',
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/campaigns/${campaign._id}`), adminFixture)
      .send({ status: 'cancelled' });

    assert.equal(res.status, 409,
      `a campaign with paid members was cancelled with no handling (${res.status})`);
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'active');
  });

  await t.test('but a NON-terminal status change still works', async () => {
    // The guard must not block pausing a campaign, editing it, or any of the
    // ordinary admin work — only the two transitions that abandon paid members.
    const builder = await M('Builder').create({
      name: 'B2', phone: `9${String(Date.now() + 1).slice(-9)}`, isActive: true,
    });
    const admin = await M('Admin').collection.insertOne({
      name: 'S', email: `s2-${Date.now()}-${process.hrtime()[1]}@example.com`, createdAt: new Date(),
    });
    const project = await M('Project').create({
      builder: builder._id, createdBy: admin.insertedId,
      basics: { name: 'P2' }, location: { city: 'Pune' },
    });
    const unitType = await M('UnitType').create({
      project: project._id, builder: builder._id, createdBy: admin.insertedId,
      config: { name: '3 BHK' },
    });
    const campaign = await M('GroupBuyCampaign').create({
      unitType: unitType._id, project: project._id, builder: builder._id,
      createdBy: admin.insertedId,
      basics: { name: 'C2' }, buyerTargets: { minBuyers: 2 },
      duration: { startDate: new Date(), endDate: new Date(Date.now() + 86400000) },
      discountPerBuyer: 100000, status: 'active',
    });
    const user = await makeUser({ role: 'user' });
    await M('CampaignMember').create({
      campaign: campaign._id, user: user._id, status: 'active', tokenStatus: 'paid',
    });

    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.put(`/api/campaigns/${campaign._id}`), adminFixture)
      .send({ status: 'paused' });

    assert.equal(res.status, 200,
      `pausing a campaign was blocked by the terminal-state guard (${res.status})`);
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'paused');
  });
});

test('cleanup: booking adminNotes appends instead of overwriting', async (t) => {
  await t.test('two status changes keep both notes', async () => {
    // Observed through the API, not read from source: a source assertion
    // survives an appendNote that returns only the new note.
    const builder = await M('Builder').create({
      name: 'B', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
    });
    const booking = await M('ProjectBooking').create({
      project: new mongoose.Types.ObjectId(),
      unitType: new mongoose.Types.ObjectId(),
      builder: builder._id,
      clientName: 'Buyer', clientPhone: '9876543210',
      status: 'confirmed',
      adminNotes: 'first observation',
    });

    const admin = await adminWithSession(api);
    await asAdmin(api.put(`/api/bookings/${booking._id}/status`), admin)
      .send({ status: 'completed', adminNotes: 'second observation' });

    const fresh = await M('ProjectBooking').findById(booking._id).lean();
    assert.match(fresh.adminNotes, /first observation/,
      'the earlier note was destroyed by the later one');
    assert.match(fresh.adminNotes, /second observation/);
  });
});

test('cleanup: public list limits are capped', async (t) => {
  await t.test('projects', async () => {
    const res = await api.get('/api/projects?limit=99999').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200);
    assert.ok((res.body.pagination?.limit ?? 60) <= 60,
      `the project list accepted an unbounded limit (${res.body.pagination?.limit})`);
  });

  await t.test('builders', async () => {
    const adminFixture = await adminWithSession(api);
    const res = await asAdmin(api.get('/api/builders?limit=99999'), adminFixture);
    assert.equal(res.status, 200);
    assert.ok((res.body.pagination?.limit ?? 60) <= 60,
      `the builder list accepted an unbounded limit (${res.body.pagination?.limit})`);
  });
});

test('cleanup: the Hubble shared secret', async (t) => {
  // The test environment carries no Hubble secret, so every call would 500 as
  // "misconfigured" — correct behaviour, but it never reaches the comparison
  // this test is about. Set one, and restore it afterwards.
  const REAL = 'a-real-hubble-secret-value';
  const saved = process.env.HUBBLE_WEBHOOK_SECRET;
  t.before(() => { process.env.HUBBLE_WEBHOOK_SECRET = REAL; });
  t.after(() => {
    if (saved === undefined) delete process.env.HUBBLE_WEBHOOK_SECRET;
    else process.env.HUBBLE_WEBHOOK_SECRET = saved;
  });

  const call = (secret) => {
    const req = api.get('/api/rewards/hubble/balance?userId=x')
      .set('X-Forwarded-For', uniqueClientIp());
    return secret === undefined ? req : req.set('X-Hubble-Secret', secret);
  };

  await t.test('a wrong secret is rejected', async () => {
    const res = await call('definitely-not-the-secret');
    assert.equal(res.status, 401, `a wrong secret was accepted (${res.status})`);
  });

  await t.test('a missing secret is rejected', async () => {
    assert.equal((await call()).status, 401);
  });

  await t.test('a secret that is a PREFIX of the real one is rejected', async () => {
    // The case a length-only or truncating comparison would let through.
    assert.equal((await call(REAL.slice(0, -1))).status, 401);
  });

  await t.test('a secret LONGER than the real one is rejected', async () => {
    // timingSafeEqual throws on a length mismatch; the length check in front of
    // it must catch this rather than let the throw become a 500.
    assert.equal((await call(REAL + 'x')).status, 401);
  });

  await t.test('it fails CLOSED when no secret is configured', async () => {
    // Never fail open: an unconfigured server must refuse, not admit everyone.
    const stashed = process.env.HUBBLE_WEBHOOK_SECRET;
    delete process.env.HUBBLE_WEBHOOK_SECRET;
    try {
      const res = await call('anything');
      // 500, specifically — not 401.
      //
      // Both refuse the caller, so accepting either would pass even with the
      // misconfiguration guard removed (an empty expected secret simply fails
      // to match). The distinction is operational: 401 says "your secret is
      // wrong", 500 says "this server was deployed without one", and only the
      // second tells whoever is on call what to actually do.
      assert.equal(res.status, 500,
        `an unconfigured secret answered ${res.status} — ops cannot tell misconfiguration from a bad caller`);
    } finally {
      if (stashed !== undefined) process.env.HUBBLE_WEBHOOK_SECRET = stashed;
    }
  });

  await t.test('and the comparison is timing-safe', () => {
    const src = strip(backend('controllers/hubbleController.js'));
    assert.match(src, /crypto\.timingSafeEqual\(/, 'the secret is compared with !== again');
  });
});

test('cleanup: the dead property status vocabulary is gone', async (t) => {
  await t.test('the visibility check no longer names statuses that cannot exist', () => {
    // 'rejected', 'suspended' and 'draft' are not in the Property status enum,
    // so the guard listing them was checking for values nothing can produce.
    // Comments stripped: the fix documents the values it removed, and naming
    // them is exactly what a raw match reads as the defect surviving.
    const src = strip(backend('controllers/propertyController.js'));
    assert.ok(!src.includes("'rejected', 'suspended', 'draft', 'pending'"),
      'the dead status vocabulary survives');
    assert.ok(!src.includes("$nin: ['rejected'"),
      'the query filter still excludes statuses that cannot exist');
  });

  await t.test('RATIFIED: status "inactive" now actually hides a property', async () => {
    // Two fields both claiming to mean inactive, only one of which worked.
    const owner = await makeOwner();
    const property = await makeProperty(owner, { isApproved: true });
    await M('Property').updateOne({ _id: property._id }, { $set: { status: 'inactive' } });

    const res = await api.get(`/api/properties/${property._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404, 'a property marked inactive is still publicly readable');
  });

  await t.test('but "pending" still hides it, as it always did', async () => {
    const owner = await makeOwner();
    const property = await makeProperty(owner, { isApproved: true });
    await M('Property').updateOne({ _id: property._id }, { $set: { status: 'pending' } });
    const res = await api.get(`/api/properties/${property._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404);
  });

  await t.test('and an active property is still visible', async () => {
    const owner = await makeOwner();
    const property = await makeProperty(owner, { isApproved: true });
    const res = await api.get(`/api/properties/${property._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200);
  });
});
