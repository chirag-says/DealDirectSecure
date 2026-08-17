/**
 * Suite 17: admin authorisation after the permission layer was retired.
 *
 * WHAT WAS REMOVED, AND WHY IT PROTECTED NOTHING.
 *
 * Five admin routes sat behind `requirePermission`. Production holds 45
 * Permission documents wired to four roles, and all three admin accounts hold
 * `super_admin`, which grants all 45. So the check passed for every admin on
 * every one of those routes: it was a lookup that always succeeded, not access
 * control.
 *
 * It could only ever FAIL, and it failed closed and site-wide. That is not
 * theoretical. Commit 79ae3ab attached `requirePermission("verifications:read")`
 * to the deal-verification routes; `verifications` is absent from the closed
 * `Permission.resource` enum, so no such document can exist, no role can grant
 * it, and every admin including super_admin got a 403. The Deal Verifications
 * page rendered "No pending verifications found" while closures piled up
 * unapproved and no user could claim a deal reward. The shipped fix was to
 * remove the guards.
 *
 * The codebase had already reached the same conclusion twice independently:
 * `rewardsController` documents why the rewards route cannot use it, and
 * `tests/reward-adjustment.test.js` asserts it stays off.
 *
 * WHAT REPLACES IT: nothing, because nothing was there. `protectAdmin` is the
 * real control and always was — session validity, fingerprint, MFA, account
 * active, not locked. This suite proves each of those still holds on exactly
 * the routes that lost the permission call.
 *
 * `requireSuperAdmin` stays on the audit log. That one has a genuine product
 * purpose and, unlike the permission layer, works without seed data: it reads
 * `role.level`, which admin creation actually sets.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync } from 'node:fs';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, ownerWithSession, buyerWithSession, makeProperty, makeLead } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

/** The five routes that carried requirePermission, and the code each demanded. */
const FORMERLY_GUARDED = [
  { method: 'get', path: () => '/api/admin/dashboard/stats', was: 'dashboard:read' },
  { method: 'get', path: () => '/api/admin/leads', was: 'leads:read' },
  { method: 'get', path: () => '/api/admin/reports', was: 'reports:read' },
];

async function leadFixture() {
  const { owner } = await ownerWithSession(api);
  const { buyer } = await buyerWithSession(api);
  const property = await makeProperty(owner);
  return makeLead(property, buyer, { propertyOwner: owner._id, status: 'new' });
}

// ---------------------------------------------------------------------------

test('an authenticated admin reaches every formerly guarded route', async (t) => {
  for (const route of FORMERLY_GUARDED) {
    await t.test(`${route.path()} no longer needs ${route.was}`, async () => {
      // The admin fixture grants NO permissions by default, which is exactly
      // what a fresh database gives one. Before this change that meant
      // getPermissions() returned [] and every one of these answered 403.
      const admin = await adminWithSession(api);

      const res = await asAdmin(api[route.method](route.path()), admin).send();

      assert.ok(res.status < 400, `${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    });
  }

  await t.test('PUT /api/admin/leads/:id no longer needs leads:update', async () => {
    const admin = await adminWithSession(api);
    const lead = await leadFixture();

    const res = await asAdmin(api.put(`/api/admin/leads/${lead._id}`), admin)
      .send({ status: 'contacted' });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal((await M('Lead').findById(lead._id).lean()).status, 'contacted');
  });

  await t.test('PUT /api/admin/reports/:id no longer needs reports:update', async () => {
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const report = await M('Report').create({
      reportedBy: buyer._id, contextType: 'property', reason: 'spam', status: 'pending',
    });

    const res = await asAdmin(api.put(`/api/admin/reports/${report._id}`), admin)
      .send({ status: 'reviewed' });

    assert.ok(res.status < 400, `${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
  });
});

// ---------------------------------------------------------------------------

test('protectAdmin still carries the whole load', async (t) => {
  for (const route of FORMERLY_GUARDED) {
    await t.test(`${route.path()} refuses an unauthenticated caller`, async () => {
      const res = await api[route.method](route.path()).send();
      assert.equal(res.status, 401, JSON.stringify(res.body).slice(0, 200));
      assert.equal(res.body.code, 'NO_SESSION');
    });
  }

  await t.test('a deactivated admin is refused', async () => {
    // The check that actually matters, and the one a permission lookup never
    // performed. Removing requirePermission must not have widened this.
    const admin = await adminWithSession(api);
    await M('Admin').findByIdAndUpdate(admin.admin._id, { isActive: false });

    const res = await asAdmin(api.get('/api/admin/leads'), admin).send();

    assert.equal(res.status, 403, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'ACCOUNT_DEACTIVATED');
  });

  await t.test('a revoked session is refused', async () => {
    const admin = await adminWithSession(api);
    await M('AdminSession').updateMany({ admin: admin.admin._id }, { isActive: false });

    const res = await asAdmin(api.get('/api/admin/leads'), admin).send();
    assert.equal(res.status, 401);
  });

  await t.test('an expired session is refused', async () => {
    const admin = await adminWithSession(api);
    await M('AdminSession').updateMany(
      { admin: admin.admin._id }, { expiresAt: new Date('2020-01-01') }
    );

    const res = await asAdmin(api.get('/api/admin/leads'), admin).send();
    assert.equal(res.status, 401);
  });

  await t.test('an unverified-MFA session is refused', async () => {
    const admin = await adminWithSession(api);
    await M('AdminSession').updateMany({ admin: admin.admin._id }, { mfaVerified: false });

    const res = await asAdmin(api.get('/api/admin/leads'), admin).send();
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'MFA_REQUIRED');
  });
});

// ---------------------------------------------------------------------------

test('the audit log keeps its role-level gate', async (t) => {
  await t.test('a level-100 admin can read it', async () => {
    // requireSuperAdmin reads role.level, which createDefaultRoles actually
    // seeds — unlike the permission layer, it works on a fresh database.
    const admin = await adminWithSession(api, { permissions: ['audit_logs:read'] });

    const res = await asAdmin(api.get('/api/admin/audit-logs'), admin).send();
    assert.ok(res.status < 400, `${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
  });

  await t.test('an admin below level 100 cannot', async () => {
    const admin = await adminWithSession(api);
    const role = await M('Role').findOneAndUpdate(
      { name: 'manager' },
      { $setOnInsert: { displayName: 'Manager', level: 50 } },
      { upsert: true, new: true }
    );
    await M('Admin').findByIdAndUpdate(admin.admin._id, { role: role._id });

    const res = await asAdmin(api.get('/api/admin/audit-logs'), admin).send();

    assert.equal(res.status, 403, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'INSUFFICIENT_ROLE_LEVEL');
  });

  await t.test('an admin with no role at all cannot', async () => {
    const admin = await adminWithSession(api);
    const res = await asAdmin(api.get('/api/admin/audit-logs'), admin).send();
    assert.equal(res.status, 403, 'level defaults to 0 when no role is set');
  });
});

// ---------------------------------------------------------------------------

test('an unresolvable permission code can no longer take a route down', async (t) => {
  await t.test('requirePermission is gone from the middleware', () => {
    // The 79ae3ab failure mode required the middleware to exist. Deleting it
    // means a future edit cannot reintroduce the outage by naming a code that
    // is not in the closed resource enum.
    assert.doesNotMatch(
      read('../../middleware/authAdmin.js'),
      /export const requirePermission/,
      'the middleware is back; a code outside Permission.resource can 403 every admin again'
    );
  });

  await t.test('no route references it', () => {
    const routes = read('../../routes/adminRoutes.js')
      .replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')
      .replace(new RegExp('//[^\\r\\n]*', 'g'), '');
    assert.doesNotMatch(routes, /requirePermission/);
  });

  await t.test('the dead permission helpers are gone from the Admin model', () => {
    const model = read('../../models/Admin.js');
    for (const method of ['hasPermission', 'hasAnyPermission', 'hasAllPermissions']) {
      assert.doesNotMatch(
        model, new RegExp(`methods\\.${method}\\s*=`),
        `${method} had zero callers and resolves permissions that no longer gate anything`
      );
    }
  });

  await t.test('the Role and Permission models still exist', () => {
    // Deliberately kept. The production collections hold 45 permissions and
    // four roles; removing the models would orphan them and make the eventual
    // cleanup migration harder to write, not easier.
    assert.ok(M('Role'), 'Role model was removed');
    assert.ok(M('Permission'), 'Permission model was removed');
  });

  await t.test('role level still resolves, because requireSuperAdmin needs it', () => {
    assert.match(read('../../models/Role.js'), /level/);
  });
});
