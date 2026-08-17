/**
 * Verify admin authorisation against dealdirect_dev after the RBAC
 * simplification.
 *
 *   node scripts/verify-admin-authz-dev.mjs
 *
 * dealdirect_dev holds no admin accounts — the anonymised copy left them out —
 * so this creates one, exercises the guards, and removes it. It refuses to run
 * anywhere but dealdirect_dev and fails if the database does not return to
 * baseline.
 *
 * Production RBAC data is NOT touched by this or by the code change. The 45
 * Permission documents and four Role documents stay exactly as they are until
 * the separate cleanup migration.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

import Admin from '../models/Admin.js';
import AdminSession from '../models/AdminSession.js';
import Role from '../models/Role.js';
import Permission from '../models/Permission.js';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
const MARKER = 'authz-verify';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName} host=${mongoose.connection.host}\n`);

if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  await mongoose.disconnect();
  process.exit(1);
}

const COUNTED = { admins: Admin, sessions: AdminSession, roles: Role, permissions: Permission };
const baseline = {};
for (const [k, M] of Object.entries(COUNTED)) baseline[k] = await M.countDocuments();
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

const made = { admins: [], roles: [] };

try {
  console.log('The permission layer is gone from the code');
  const authAdmin = await import('../middleware/authAdmin.js');
  check('requirePermission is not exported', authAdmin.requirePermission === undefined);
  check('protectAdmin is still exported', typeof authAdmin.protectAdmin === 'function');
  check('requireSuperAdmin is still exported', typeof authAdmin.requireSuperAdmin === 'function');
  check('requireRoleLevel is still exported', typeof authAdmin.requireRoleLevel === 'function');

  console.log('\nThe Admin model no longer carries dead permission helpers');
  const proto = Admin.schema.methods;
  check('hasPermission removed', proto.hasPermission === undefined);
  check('hasAnyPermission removed', proto.hasAnyPermission === undefined);
  check('hasAllPermissions removed', proto.hasAllPermissions === undefined);
  check('getPermissions kept for the cleanup migration', typeof proto.getPermissions === 'function');

  console.log('\nRole level resolves against the real database');
  // The bug this phase found: Admin.role is Mixed, so a bare populate("role")
  // silently no-ops and every admin reads as level 0 — which meant
  // requireSuperAdmin denied everyone, including genuine level-100 accounts.
  const role = await Role.findOneAndUpdate(
    { name: 'super_admin' },
    { $setOnInsert: { displayName: 'Super Administrator', level: 100 } },
    { upsert: true, new: true }
  );
  if (baseline.roles === 0) made.roles.push(role._id);

  const admin = await Admin.create({
    name: MARKER, email: `${MARKER}@example.invalid`,
    password: 'TestPassw0rd!23', isActive: true, role: role._id,
  });
  made.admins.push(admin._id);

  const bare = await Admin.findById(admin._id).populate('role');
  check('a bare populate on a Mixed path still resolves nothing',
    bare.role?.level === undefined, 'this is the bug, confirmed against the real database');

  const fixed = await Admin.findById(admin._id).populate({ path: 'role', model: 'Role' });
  check('naming the model resolves it', fixed.role?.level === 100, `level=${fixed.role?.level}`);

  console.log('\nProduction RBAC data model is untouched');
  check('Role model still registered', !!mongoose.model('Role'));
  check('Permission model still registered', !!mongoose.model('Permission'));
  check('no permission document was created by this run',
    (await Permission.countDocuments()) === baseline.permissions);
} finally {
  const removed = {
    admins: (await Admin.deleteMany({ _id: { $in: made.admins } })).deletedCount,
    roles: (await Role.deleteMany({ _id: { $in: made.roles } })).deletedCount,
  };
  console.log('\ncleanup:', JSON.stringify(removed));

  const final = {};
  for (const [k, M] of Object.entries(COUNTED)) final[k] = await M.countDocuments();
  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('final   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exitCode = fail === 0 && drift.length === 0 ? 0 : 1;
}
