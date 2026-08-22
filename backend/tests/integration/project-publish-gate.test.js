/**
 * Stage 3 — the project publish lifecycle.
 *
 * Today a project is public the instant an admin clicks create, and not one
 * field is required. The schema comment says incremental authoring is the
 * design — "no data field is compulsory" — but `isActive` defaults true, so
 * intent and mechanism contradict each other and the buyer sees whatever the
 * admin had typed by then.
 *
 * This adds the missing half: projects land in DRAFT (invisible), and going
 * public is an explicit act that runs a server-side checklist.
 *
 * The rules are BLOCK or WARN. Every BLOCK traces to an observed failure —
 * imageless cards, ₹0-token bookings, a deactivated builder still selling.
 * WARNs (brochure, RERA number, coordinates) are shown and never block, because
 * the dev census says admins skip exactly those and a gate nobody can pass is a
 * gate nobody uses.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, seedTaxonomy } from './setup/factories.js';

import {
  evaluateProjectReadiness, isUnitTypePublishable,
  PROJECT_BLOCK_RULES, UNIT_BLOCK_RULES,
} from '../../utils/projectPublishGuard.js';

let api;
test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

/** A project that passes every BLOCK rule, plus overrides. */
async function makePublishable(overrides = {}, unitOverrides = {}) {
  const builder = await M('Builder').create({
    name: 'Ready Builder', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
  });
  const admin = await M('Admin').collection.insertOne({
    name: 'Seed', email: `s-${Date.now()}-${process.hrtime()[1]}@example.com`, createdAt: new Date(),
  });

  const project = await M('Project').create({
    builder: builder._id, createdBy: admin.insertedId,
    basics: { name: 'Ready Project', category: 'Residential' },
    location: { city: 'Pune' },
    media: { exteriorImages: ['https://res.cloudinary.com/x/a.jpg'] },
    ...overrides,
  });

  const unitType = await M('UnitType').create({
    project: project._id, builder: builder._id, createdBy: admin.insertedId,
    config: { name: '2 BHK' },
    area: { carpetSqft: 900 },
    pricing: { basePrice: 5_000_000 },
    inventory: { totalUnits: 10, availableUnits: 10 },
    paymentTerms: { bookingAmount: 50_000 },
    isActive: true,
    ...unitOverrides,
  });

  return { builder, project, unitType, adminId: admin.insertedId };
}

const readiness = async (project) => {
  const fresh = await M('Project').findById(project._id).lean();
  return evaluateProjectReadiness(fresh, {
    builder: await M('Builder').findById(fresh.builder).lean(),
    unitTypes: await M('UnitType').find({ project: fresh._id }).lean(),
  });
};

// ---------------------------------------------------------------------------
// The lifecycle field
// ---------------------------------------------------------------------------

test('a project is not public until someone publishes it', async (t) => {
  await t.test('the schema carries a publication status', () => {
    const path = M('Project').schema.path('publication.status');
    assert.ok(path, 'Project has no publication.status');
    assert.deepEqual([...path.enumValues].sort(), ['draft', 'published']);
  });

  await t.test('and it defaults to draft', async () => {
    const { project } = await makePublishable();
    assert.equal(project.publication.status, 'draft',
      'a newly created project is public immediately — the whole defect');
  });

  await t.test('a draft is invisible to the public list', async () => {
    const { project } = await makePublishable();
    const res = await api.get('/api/projects').set('X-Forwarded-For', uniqueClientIp());
    const ids = (res.body.data || []).map((p) => String(p._id));
    assert.ok(!ids.includes(String(project._id)), 'a draft project is publicly listed');
  });

  await t.test('a draft 404s on its own detail page', async () => {
    const { project } = await makePublishable();
    const res = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404, 'a draft project is publicly readable');
  });

  await t.test('but an admin can see it', async () => {
    const { project } = await makePublishable();
    const admin = await adminWithSession(api);
    const res = await asAdmin(api.get(`/api/projects/${project._id}`), admin);
    assert.equal(res.status, 200, 'an admin cannot see their own draft');
  });
});

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

test('publishing runs the checklist', async (t) => {
  const publish = (project, admin) =>
    asAdmin(api.post(`/api/projects/${project._id}/publish`), admin).send({});

  await t.test('a complete project publishes and becomes visible', async () => {
    const { project } = await makePublishable();
    const admin = await adminWithSession(api);

    const res = await publish(project, admin);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));

    const fresh = await M('Project').findById(project._id).lean();
    assert.equal(fresh.publication.status, 'published');
    assert.ok(fresh.publication.publishedAt, 'publishedAt was not stamped');
    assert.ok(fresh.publication.publishedBy, 'publishedBy was not recorded');

    const pub = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(pub.status, 200, 'a published project is still not public');
  });

  for (const [label, patch] of [
    ['no name', { 'basics.name': null }],
    ['no category', { 'basics.category': null }],
    ['no city', { 'location.city': null }],
    ['no images', { 'media.exteriorImages': [] }],
  ]) {
    await t.test(`refuses: ${label}`, async () => {
      const { project } = await makePublishable();
      await M('Project').updateOne({ _id: project._id }, { $set: patch });
      const admin = await adminWithSession(api);

      const res = await publish(project, admin);
      assert.equal(res.status, 422, `expected a refusal, got ${res.status}`);
      assert.ok(Array.isArray(res.body.blockers) && res.body.blockers.length > 0,
        'the refusal listed no blockers — the admin cannot act on it');
      assert.equal(
        (await M('Project').findById(project._id).lean()).publication.status, 'draft'
      );
    });
  }

  await t.test('refuses when the builder is inactive', async () => {
    // The audit case: deactivating a builder left their projects on sale.
    const { project, builder } = await makePublishable();
    await M('Builder').updateOne({ _id: builder._id }, { $set: { isActive: false } });
    const admin = await adminWithSession(api);

    const res = await publish(project, admin);
    assert.equal(res.status, 422);
    assert.match(JSON.stringify(res.body.blockers), /builder/i);
  });

  await t.test('refuses when no unit type is sellable', async () => {
    const { project, unitType } = await makePublishable();
    await M('UnitType').updateOne({ _id: unitType._id },
      { $set: { 'paymentTerms.bookingAmount': null } });
    const admin = await adminWithSession(api);

    const res = await publish(project, admin);
    assert.equal(res.status, 422, 'a project with no bookable unit type published');
    assert.match(JSON.stringify(res.body.blockers), /unit type/i);
  });

  await t.test('WARNs never block', async () => {
    // No brochure, no RERA number, no coordinates — 0/7, 5/7 and 7/7 in the
    // real census. Publishing must still succeed.
    const { project } = await makePublishable();
    const admin = await adminWithSession(api);

    const res = await publish(project, admin);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.ok(res.body.warnings.length > 0, 'the warnings were not reported at all');
    assert.match(JSON.stringify(res.body.warnings), /brochure|rera/i);
  });

  await t.test('the RERA number is a warning, not a blocker (ratified)', async () => {
    // Decided 2026-08-22: display the number, do not gate on it.
    const { project } = await makePublishable();
    const r = await readiness(project);
    assert.ok(!JSON.stringify(r.blockers).match(/rera/i), 'RERA became a blocker');
    assert.match(JSON.stringify(r.warnings), /rera/i, 'RERA is not even warned about');
  });
});

// ---------------------------------------------------------------------------
// Unpublish
// ---------------------------------------------------------------------------

test('a published project can be taken down again', async (t) => {
  await t.test('unpublish returns it to draft and hides it', async () => {
    const { project } = await makePublishable();
    const admin = await adminWithSession(api);
    await asAdmin(api.post(`/api/projects/${project._id}/publish`), admin).send({});

    const res = await asAdmin(api.post(`/api/projects/${project._id}/unpublish`), admin).send({});
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal((await M('Project').findById(project._id).lean()).publication.status, 'draft');

    const pub = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(pub.status, 404);
  });

  await t.test('existing bookings are untouched by an unpublish', async () => {
    // Taking a listing down must not invalidate money already taken against it.
    const { project, unitType, builder } = await makePublishable();
    const admin = await adminWithSession(api);
    await asAdmin(api.post(`/api/projects/${project._id}/publish`), admin).send({});

    const booking = await M('ProjectBooking').create({
      project: project._id, unitType: unitType._id, builder: builder._id,
      clientName: 'Buyer', clientPhone: '9876543210', status: 'confirmed',
      payment: { tokenAmount: 50_000, utrNumber: 'KEEP-1', status: 'verified' },
    });

    await asAdmin(api.post(`/api/projects/${project._id}/unpublish`), admin).send({});
    const fresh = await M('ProjectBooking').findById(booking._id).lean();
    assert.equal(fresh.status, 'confirmed');
    assert.equal(fresh.payment.utrNumber, 'KEEP-1');
  });
});

// ---------------------------------------------------------------------------
// The guard as a pure function
// ---------------------------------------------------------------------------

test('the readiness checklist is a pure, inspectable function', async (t) => {
  await t.test('it reports every rule, passing or not', async () => {
    const { project } = await makePublishable();
    const r = await readiness(project);
    assert.ok(Array.isArray(r.checklist), 'no checklist array');
    assert.ok(r.checklist.length >= PROJECT_BLOCK_RULES.length,
      'the checklist omits rules — the admin cannot see what is missing');
    for (const item of r.checklist) {
      assert.ok(typeof item.rule === 'string' && item.rule);
      assert.ok(['block', 'warn'].includes(item.level));
      assert.equal(typeof item.passed, 'boolean');
      assert.ok(item.message, `rule ${item.rule} has no human message`);
    }
  });

  await t.test('canPublish is exactly "no blockers"', async () => {
    const { project } = await makePublishable();
    const ok = await readiness(project);
    assert.equal(ok.canPublish, true);
    assert.equal(ok.blockers.length, 0);

    await M('Project').updateOne({ _id: project._id }, { $set: { 'basics.name': null } });
    const bad = await readiness(project);
    assert.equal(bad.canPublish, false);
    assert.equal(bad.blockers.length > 0, true);
  });

  await t.test('a missing project is not silently publishable', () => {
    const r = evaluateProjectReadiness(null, {});
    assert.equal(r.canPublish, false);
  });
});

test('unit-type publishability', async (t) => {
  const base = () => ({
    config: { name: '2 BHK' },
    area: { carpetSqft: 900 },
    pricing: { basePrice: 5_000_000 },
    inventory: { totalUnits: 10, availableUnits: 10 },
    paymentTerms: { bookingAmount: 50_000 },
    isActive: true,
  });

  await t.test('a complete residential unit type passes', () => {
    assert.equal(isUnitTypePublishable(base()).ok, true);
  });

  for (const [label, patch] of [
    ['no name', { config: {} }],
    ['no base price', { pricing: {} }],
    ['no total units', { inventory: { availableUnits: 5 } }],
    ['no booking amount', { paymentTerms: {} }],
    ['inactive', { isActive: false }],
  ]) {
    await t.test(`fails: ${label}`, () => {
      const ut = { ...base(), ...patch };
      assert.equal(isUnitTypePublishable(ut).ok, false, `${label} was accepted`);
    });
  }

  await t.test('RATIFIED: carpet area blocks a residential unit type', () => {
    // Carpet area is the legal basis of sale under RERA, and the price display
    // computes ₹/sqft from it. 8/8 real unit types already carry it.
    const ut = { ...base(), area: {} };
    const r = isUnitTypePublishable(ut);
    assert.equal(r.ok, false, 'a residential unit type published with no carpet area');
    assert.match(JSON.stringify(r.reasons), /carpet/i);
  });

  await t.test('but a plot blocks on plot area instead', () => {
    // plotAreaSqft is the equivalent for Plotted Development; carpet is
    // meaningless there and must not be demanded.
    const plot = { ...base(), area: { plotAreaSqft: 2400 } };
    assert.equal(isUnitTypePublishable(plot, { category: 'Plotted Development' }).ok, true);

    const noPlot = { ...base(), area: {} };
    assert.equal(isUnitTypePublishable(noPlot, { category: 'Plotted Development' }).ok, false);
  });

  await t.test('availableUnits of 0 is legal — a sold-out type is still valid', () => {
    const soldOut = { ...base(), inventory: { totalUnits: 10, availableUnits: 0 } };
    assert.equal(isUnitTypePublishable(soldOut).ok, true,
      'a sold-out configuration was treated as unpublishable');
  });

  await t.test('undefined availableUnits is NOT legal', () => {
    const unset = { ...base(), inventory: { totalUnits: 10 } };
    assert.equal(isUnitTypePublishable(unset).ok, false);
  });

  await t.test('the rule sets are exported so the Admin UI cannot drift', () => {
    assert.ok(PROJECT_BLOCK_RULES.length > 0);
    assert.ok(UNIT_BLOCK_RULES.length > 0);
  });
});

// ---------------------------------------------------------------------------
// Migration safety
// ---------------------------------------------------------------------------

test('existing projects are not hidden by the upgrade', async (t) => {
  await t.test('a legacy active project reads as published', async () => {
    // The 7 real projects predate `publication` entirely. If the read path
    // required the new field they would all vanish from the site on deploy.
    const { project } = await makePublishable();
    await M('Project').collection.updateOne(
      { _id: project._id },
      { $unset: { publication: '' }, $set: { isActive: true } }
    );

    const res = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200,
      'a pre-existing published project disappeared — every live project would 404');
  });

  await t.test('and it still appears in the public LIST', async () => {
    // The detail page and the list are two separate code paths. Mutation
    // testing caught this gap: breaking the list filter's legacy clause failed
    // no test, because only the detail route was covered. A legacy project
    // that 200s on its own URL but is missing from /projects is still gone as
    // far as every visitor is concerned.
    const { project } = await makePublishable();
    await M('Project').collection.updateOne(
      { _id: project._id },
      { $unset: { publication: '' }, $set: { isActive: true } }
    );

    const res = await api.get('/api/projects').set('X-Forwarded-For', uniqueClientIp());
    const ids = (res.body.data || []).map((p) => String(p._id));
    assert.ok(ids.includes(String(project._id)),
      'a pre-existing project is missing from the public list');
  });

  await t.test('a legacy deactivated project stays hidden', async () => {
    const { project } = await makePublishable();
    await M('Project').collection.updateOne(
      { _id: project._id },
      { $unset: { publication: '' }, $set: { isActive: false } }
    );
    const res = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404);
  });
});
