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

export async function makeNotification(user, overrides = {}) {
  const Notification = mongoose.model('Notification');
  const n = next();
  return Notification.create({
    user: user._id || user,
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
