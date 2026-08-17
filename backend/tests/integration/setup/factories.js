/**
 * Test data factories.
 *
 * Everything here is synthetic. Emails are @example.com (RFC 2606, reserved and
 * undeliverable), phone numbers come from the 99999xxxxx block used only for
 * fixtures, and names are obviously fake. No production identifier, real
 * customer record, or exported document is used anywhere in the suite.
 *
 * Users are inserted through the Mongoose model rather than the registration
 * endpoint. That is deliberate: registration is an OTP flow, and making every
 * authorisation test walk through OTP issuance would couple unrelated suites to
 * the messaging code and cost a round trip per fixture. The auth suite drives
 * the real endpoints; other suites only need a user that exists.
 *
 * Counters make identifiers unique within a run. They are not reset by
 * truncation, so a test cannot accidentally collide with a previous test's
 * leftover unique index entry.
 */

import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { CANONICAL_TAXONOMY } from '../../../config/taxonomy.js';

let seq = 0;
const next = () => ++seq;

/** Password used for every fixture user. Synthetic; satisfies the app's policy. */
export const TEST_PASSWORD = 'TestPassw0rd!23';

/**
 * Cost factor must match the registration controller (userController.js:276),
 * so a fixture user is indistinguishable from a registered one.
 *
 * The hashing is explicit here because the User model has NO password-hashing
 * pre-save hook, `userModel.js`'s only pre-save hook generates referral codes.
 * Every hash in the application is produced by a controller. Assigning a plain
 * string to `password` and saving therefore stores it in clear, which is how
 * the first version of this factory silently produced users that could not log
 * in. Anything that writes a password outside a controller has to hash it
 * itself.
 */
const BCRYPT_ROUNDS = 12;

/** Cached so the suite pays the bcrypt cost once rather than per fixture. */
let cachedHash = null;
async function testPasswordHash() {
  if (!cachedHash) cachedHash = await bcrypt.hash(TEST_PASSWORD, BCRYPT_ROUNDS);
  return cachedHash;
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/**
 * Create a verified user. `role` is one of user | buyer | owner.
 * Pass `password` in overrides to set a different plaintext.
 */
export async function makeUser(overrides = {}) {
  const User = mongoose.model('User');
  const n = next();
  const { password, ...rest } = overrides;
  const doc = new User({
    name: `Test User ${n}`,
    email: `test-user-${n}@example.com`,
    password: password
      ? await bcrypt.hash(password, BCRYPT_ROUNDS)
      : await testPasswordHash(),
    phone: `99999${String(10000 + n).slice(-5)}`,
    role: 'user',
    isVerified: true,
    ...rest,
  });
  await doc.save();
  return doc;
}

export const makeOwner = (o = {}) => makeUser({ role: 'owner', ...o });
export const makeBuyer = (o = {}) => makeUser({ role: 'buyer', ...o });

// ---------------------------------------------------------------------------
// Admins
// ---------------------------------------------------------------------------

/**
 * A fixed user agent for admin fixtures.
 *
 * The session fingerprint is derived from the user agent and the client IP, so
 * the session has to be built from the same values the request will carry. A
 * mismatch is not a test failure with a useful message: protectAdmin revokes
 * the session and returns SESSION_FINGERPRINT_MISMATCH, which reads like an
 * authorisation bug rather than a fixture bug.
 */
export const ADMIN_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36';

/**
 * Unlike User, the Admin model hashes its own password in a pre-save hook and
 * validates the plaintext against a strength regex first. So this factory
 * passes the plaintext and lets the model do the work; handing it a bcrypt hash
 * fails the strength check with a message that reads like a fixture typo.
 */
export async function makeAdmin(overrides = {}) {
  const Admin = mongoose.model('Admin');
  const n = next();
  return Admin.create({
    name: `Test Admin ${n}`,
    email: `test-admin-${n}@example.com`,
    password: TEST_PASSWORD,
    isActive: true,
    ...overrides,
  });
}

/**
 * An admin plus a live, MFA-verified session.
 *
 * The session is built directly rather than through the login endpoint, because
 * the login path requires a TOTP code from a real authenticator secret. What is
 * under test here is what a legitimately authenticated admin can do, not how
 * they authenticated, and `tests/admin-auth.test.js` already covers the gate
 * itself.
 *
 * `mfaVerified` is set explicitly. protectAdmin refuses every admin route
 * without it, and createSession deliberately never sets it, so a fixture that
 * omitted it would 403 on every call.
 */
/**
 * Grant an admin a role carrying the given permission codes.
 *
 * FIVE admin routes used to sit behind `requirePermission`. Phase 3F removed
 * that layer: every admin held every permission, so it separated nothing, while
 * a code outside the closed `Permission.resource` enum 403'd the whole panel
 * (commit 79ae3ab). No route requires a permission today.
 *
 * The helper is kept because `Role` and `Permission` still exist and the
 * production collections are untouched pending the cleanup migration, and
 * because it is how a fixture gets a Role at all — `requireSuperAdmin` reads
 * `role.level`, so the audit-log tests need one.
 */
export async function grantPermissions(admin, codes) {
  if (!codes.length) return admin;
  const Permission = mongoose.model('Permission');
  const Role = mongoose.model('Role');

  const permissionIds = [];
  for (const code of codes) {
    const [resource, action] = code.split(':');
    const doc = await Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, resource, action } },
      { upsert: true, new: true }
    );
    permissionIds.push(doc._id);
  }

  // `Role.name` is a closed enum too, so a fixture cannot invent a role name.
  // Reusing `super_admin` matches production, where all three admin accounts
  // hold that role and it is simply the internal name for "Admin".
  const role = await Role.findOneAndUpdate(
    { name: 'super_admin' },
    { $set: { permissions: permissionIds }, $setOnInsert: { displayName: 'Super Administrator', level: 100 } },
    { upsert: true, new: true }
  );

  admin.role = role._id;
  await admin.save();
  return admin;
}

/**
 * `permissions` grants the listed codes. Defaults to none, which is what a
 * fresh database actually gives an admin.
 */
export async function adminWithSession(api, { permissions = [], ...overrides } = {}) {
  const AdminSession = mongoose.model('AdminSession');
  const admin = await makeAdmin(overrides);
  await grantPermissions(admin, permissions);

  const { uniqueClientIp } = await import('./app.js');
  const ip = uniqueClientIp();

  // Shaped like the request Supertest will send, so the fingerprint matches.
  const fakeReq = {
    headers: { 'user-agent': ADMIN_USER_AGENT, 'x-forwarded-for': ip },
    ip,
    connection: { remoteAddress: ip },
  };

  const sessionToken = AdminSession.generateToken();
  await AdminSession.create({
    admin: admin._id,
    sessionToken,
    fingerprint: AdminSession.generateFingerprint(fakeReq),
    fingerprintData: AdminSession.generateFingerprintData(fakeReq),
    ipAddress: ip,
    userAgent: ADMIN_USER_AGENT,
    deviceInfo: { browser: 'Chrome', os: 'Windows', device: 'Desktop' },
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    mfaVerified: true,
  });

  return { admin, ip, cookies: [`admin_session=${sessionToken}`] };
}

/** Attach an admin fixture's session, IP and user agent to a Supertest request. */
export function asAdmin(req, { ip, cookies }) {
  return req
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ADMIN_USER_AGENT)
    .set('Cookie', cookies);
}

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/**
 * Category is the top level, PropertyType the second, and a property type
 * belongs to a category. That is now true of the names as well as the shape:
 * the two collections used to hold each other's contents, which is what the
 * Phase 3B migration corrected.
 */
/**
 * Seed the canonical taxonomy into the test database.
 *
 * Required by any suite that creates a property through the API. The
 * server-side consistency contract resolves categoryName and propertyTypeName
 * against real documents and rejects anything it cannot find exactly, so a
 * database with no taxonomy rejects every create. That is the correct
 * production behaviour, and it means the harness has to seed the same
 * vocabulary the application ships with rather than inventing fixtures.
 *
 * Idempotent: safe to call in `before` and again after a truncate.
 */
export async function seedTaxonomy() {
  const Category = mongoose.model('Category');
  const PropertyType = mongoose.model('PropertyType');
  const categories = new Map();

  for (const categoryName of Object.keys(CANONICAL_TAXONOMY)) {
    const doc = await Category.findOneAndUpdate(
      { name: categoryName }, { $setOnInsert: { name: categoryName } },
      { upsert: true, new: true }
    );
    categories.set(categoryName, doc);
  }

  const types = new Map();
  for (const [categoryName, typeNames] of Object.entries(CANONICAL_TAXONOMY)) {
    const category = categories.get(categoryName)._id;
    for (const name of typeNames) {
      const doc = await PropertyType.findOneAndUpdate(
        { name, category }, { $setOnInsert: { name, category } },
        { upsert: true, new: true }
      );
      types.set(name, doc);
    }
  }

  return { categories, types };
}

/** The canonical pair every fixture property uses unless told otherwise. */
export const DEFAULT_TAXONOMY = Object.freeze({
  categoryName: 'Residential',
  propertyTypeName: 'Apartment / Flat',
});

export async function makeCategory(overrides = {}) {
  const Category = mongoose.model('Category');
  const n = next();
  return Category.create({ name: `Test Category ${n}`, ...overrides });
}

export async function makePropertyType(overrides = {}) {
  const PropertyType = mongoose.model('PropertyType');
  const n = next();
  const category = overrides.category || (await makeCategory())._id;
  return PropertyType.create({ name: `Test Type ${n}`, ...overrides, category });
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/**
 * Create a property owned by `owner`. Written straight to the collection via
 * the model so tests that are not about creation do not depend on the create
 * endpoint's validation rules.
 */
export async function makeProperty(owner, overrides = {}) {
  const Property = mongoose.model('Property');
  const n = next();
  return Property.create({
    title: `Test Property ${n}`,
    description: `Synthetic fixture property ${n}.`,
    owner: owner?._id || owner,
    price: 2500000,
    listingType: 'Sell',
    status: 'active',
    location: { city: 'Testville', state: 'Test State', locality: `Sector ${n}` },
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Leads
// ---------------------------------------------------------------------------

export async function makeLead(property, buyer, overrides = {}) {
  const Lead = mongoose.model('Lead');
  return Lead.create({
    property: property._id,
    propertyOwner: property.owner,
    user: buyer._id,
    userSnapshot: { name: buyer.name, email: buyer.email, phone: buyer.phone },
    status: 'new',
    source: 'website',
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/**
 * A notification created the way the application creates one.
 *
 * Goes through notifyUser rather than Notification.create. Since Phase 3E
 * delivery lives in the service, not in a model hook, so a raw create persists
 * without emailing — and `notifications.test.js` opens with a control asserting
 * that creating a notification DOES attempt an email, precisely so its later
 * "sent no email" assertions cannot pass vacuously. A factory that wrote the
 * document directly would break that control and quietly hollow out every
 * assertion after it.
 */
export async function makeNotification(user, overrides = {}) {
  const { notifyUser } = await import('../../../services/notificationService.js');
  const n = next();
  return notifyUser(user._id || user, {
    title: `Test Notification ${n}`,
    message: `Synthetic notification body ${n}.`,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/**
 * Log in through the real endpoint and return the cookie jar.
 *
 * Uses the login route, not a hand-minted JWT, because a hand-minted token
 * would skip whatever the login path actually sets, and an authorisation test
 * built on a token the application never issued proves nothing about the
 * application.
 *
 * Each login gets its own client IP so the 5-per-15-minute auth limiter does
 * not exhaust partway through a suite.
 */
export async function loginAs(api, user, { ip, password = TEST_PASSWORD } = {}) {
  const { uniqueClientIp, cookiesFrom } = await import('./app.js');
  const res = await api
    .post('/api/users/login')
    .set('X-Forwarded-For', ip || uniqueClientIp())
    .send({ email: user.email, password });

  if (res.status !== 200) {
    throw new Error(
      `[factories] loginAs failed for ${user.email}: ${res.status} ${JSON.stringify(res.body)}`
    );
  }
  return cookiesFrom(res);
}

/** An owner plus a live session, the most common fixture pair. */
export async function ownerWithSession(api, overrides = {}) {
  const owner = await makeOwner(overrides);
  const cookies = await loginAs(api, owner);
  return { owner, cookies };
}

/** A buyer plus a live session. */
export async function buyerWithSession(api, overrides = {}) {
  const buyer = await makeBuyer(overrides);
  const cookies = await loginAs(api, buyer);
  return { buyer, cookies };
}
