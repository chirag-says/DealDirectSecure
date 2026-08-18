/**
 * Verify the admin property manager bounds against dealdirect_dev (Phase 4.7).
 *
 *   node scripts/verify-admin-bounds-dev.mjs
 *
 * Walks every page of the real corpus and checks the properties that matter on
 * a management screen: no record disappears between pages, none appears twice,
 * the total describes the filter rather than the page, and a filtered set
 * partitions the same way.
 *
 * Read-only. It creates an admin session in memory only — no Admin document is
 * written — and asserts the database is unchanged.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import supertest from 'supertest';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
process.env.NODE_ENV = 'development';

const { app } = await import('../server.js');
await new Promise((r) => setTimeout(r, 1500));

const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName}\n`);
if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  process.exit(1);
}

const api = supertest(app);
const Property = mongoose.model('Property');
const Admin = mongoose.model('Admin');
const AdminSession = mongoose.model('AdminSession');
const Role = mongoose.model('Role');

const baseline = {
  properties: await Property.countDocuments(),
  admins: await Admin.countDocuments(),
  sessions: await AdminSession.countDocuments(),
};
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

// A throwaway admin + session, removed in the finally block.
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36';
const IP = '10.99.99.1';
const made = { admins: [], sessions: [] };

const role = await Role.findOne({ name: 'super_admin' });
const admin = await Admin.create({
  name: 'ADMIN_BOUNDS_VERIFY', email: 'admin-bounds-verify@example.invalid',
  password: 'TestPassw0rd!23', isActive: true, role: role?._id,
});
made.admins.push(admin._id);

const fakeReq = { headers: { 'user-agent': UA, 'x-forwarded-for': IP }, ip: IP, connection: { remoteAddress: IP } };
const token = AdminSession.generateToken();
const session = await AdminSession.create({
  admin: admin._id, sessionToken: token,
  fingerprint: AdminSession.generateFingerprint(fakeReq),
  fingerprintData: AdminSession.generateFingerprintData(fakeReq),
  ipAddress: IP, userAgent: UA,
  deviceInfo: { browser: 'Chrome', os: 'Windows', device: 'Desktop' },
  expiresAt: new Date(Date.now() + 3600_000), mfaVerified: true,
});
made.sessions.push(session._id);

const fetchAdmin = (query = '') =>
  api.get(`/api/properties/admin/all${query}`)
    .set('X-Forwarded-For', IP).set('User-Agent', UA).set('Cookie', `admin_session=${token}`);

const kb = (n) => `${(n / 1024).toFixed(1)} KB`;

try {
  console.log('Page walk over the real corpus');
  {
    const first = await fetchAdmin('?limit=20');
    if (first.status !== 200) {
      check('the endpoint answered', false, `status=${first.status} ${JSON.stringify(first.body).slice(0, 120)}`);
    } else {
      const { total, pages, limit } = first.body.pagination;
      console.log(`    total=${total}  pages=${pages}  limit=${limit}  payload/page=${kb(Buffer.byteLength(JSON.stringify(first.body)))}`);

      const seen = [];
      for (let p = 1; p <= pages; p += 1) {
        const res = await fetchAdmin(`?limit=20&page=${p}`);
        seen.push(...res.body.data.map((d) => String(d._id)));
        console.log(`    page ${p}: ${res.body.data.length} docs, hasMore=${res.body.pagination.hasMore}`);
      }

      check('every record appears exactly once across pages',
        seen.length === total && new Set(seen).size === total,
        `${seen.length} collected, ${new Set(seen).size} unique, ${total} expected`);

      check('total matches the collection', total === baseline.properties,
        `${total} vs ${baseline.properties} documents`);

      const unbounded = await fetchAdmin('?limit=200000');
      check('an absurd limit is clamped', unbounded.body.pagination.limit === 5000,
        `reported limit=${unbounded.body.pagination.limit}`);
    }
  }

  console.log('\nA filtered set partitions the same way');
  {
    const first = await fetchAdmin('?status=listed&limit=10');
    const { total, pages } = first.body.pagination;
    const seen = [];
    for (let p = 1; p <= pages; p += 1) {
      const res = await fetchAdmin(`?status=listed&limit=10&page=${p}`);
      seen.push(...res.body.data.map((d) => String(d._id)));
    }
    const approved = await Property.countDocuments({ isApproved: true });

    console.log(`    status=listed  total=${total}  pages=${pages}  approved in db=${approved}`);
    check('the filter total matches the database', total === approved);
    check('no gaps and no duplicates under a filter',
      seen.length === total && new Set(seen).size === total,
      `${seen.length} collected, ${new Set(seen).size} unique`);
    check('every returned document really is approved',
      first.body.data.every((d) => d.isApproved === true));
  }

  console.log('\nResponse compatibility');
  {
    const res = await fetchAdmin('?limit=20');
    check('success and data unchanged', res.body.success === true && Array.isArray(res.body.data));
    check('count still describes this response', res.body.count === res.body.data.length);
    check('pagination is present and complete',
      ['total', 'limit', 'page', 'pages', 'hasMore'].every((k) => k in res.body.pagination),
      JSON.stringify(res.body.pagination));
  }
} finally {
  await AdminSession.deleteMany({ _id: { $in: made.sessions } });
  await Admin.deleteMany({ _id: { $in: made.admins } });

  const final = {
    properties: await Property.countDocuments(),
    admins: await Admin.countDocuments(),
    sessions: await AdminSession.countDocuments(),
  };
  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('\nfinal   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
}
