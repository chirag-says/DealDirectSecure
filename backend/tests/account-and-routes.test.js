/**
 * Account deletion protection + legacy upload route removal
 *
 * Source-level assertions. These paths need a live database (and a replica set
 * for the property transaction), so these pin the guards rather than exercise
 * them. Replace with integration tests once a test database exists.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §6.6 (account deletion),
 * §9.1 (second unhardened create route).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { USER_CASCADE } from '../utils/aggregateDelete.js';
import { readFileSync } from 'node:fs';

/**
 * Read a source file with comments removed.
 *
 * These assertions are about executable code. Several of the removals below
 * deliberately leave an explanatory comment naming the thing that was removed
 * ("multer.diskStorage", "all associated data ..."), so a raw text match would
 * read the tombstone as the body and fail. Line endings are CRLF here, so the
 * line-comment pattern excludes \r explicitly rather than relying on $.
 */
const read = (rel) =>
  readFileSync(new URL(rel, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\r\n]*/g, '');

/** Raw source, comments intact — for assertions about documentation. */
const readRaw = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

const userRoutes = read('../routes/userRoutes.js');
const userController = read('../controllers/userController.js');
const server = read('../server.js');
const userControllerRaw = readRaw('../controllers/userController.js');

describe('legacy local-disk upload route is gone', () => {
  test('POST /users/add-property is no longer registered', () => {
    // Match a route registration, not the explanatory comment left in its place.
    assert.doesNotMatch(
      userRoutes,
      /router\.post\(\s*["']\/add-property["']/,
      'the unhardened duplicate create route is registered again'
    );
  });

  test('no multer disk storage remains in the route layer', () => {
    assert.doesNotMatch(
      userRoutes,
      /multer\.diskStorage/,
      'disk storage writes caller-controlled bytes into the publicly served ./uploads'
    );
    assert.doesNotMatch(userRoutes, /localUpload/, 'localUpload should be gone with the route');
  });

  test('the multer import is dropped now that nothing uses it', () => {
    assert.doesNotMatch(userRoutes, /^import multer from/m);
  });

  test('the validated Cloudinary pipeline is still wired for profile uploads', () => {
    // Guards against over-deletion: memoryUpload + validateAndUploadToCloudinary
    // must survive, they are the good path.
    assert.match(userRoutes, /memoryUpload/);
    assert.match(userRoutes, /validateAndUploadToCloudinary/);
    assert.match(userRoutes, /uploadConcurrencyGuard/);
  });
});

describe('account deletion is re-authenticated', () => {
  const fn = (() => {
    const start = userController.indexOf('export const deleteAccount');
    const next = userController.indexOf('\nexport const ', start + 10);
    return userController.slice(start, next === -1 ? userController.length : next);
  })();

  test('a password is required in the request body', () => {
    assert.match(fn, /req\.body/, 'handler must read a confirmation password');
    assert.match(fn, /PASSWORD_REQUIRED/);
  });

  test('the password is verified with bcrypt before anything is deleted', () => {
    // The cascade moved into deleteUserAggregate, so `deleteMany` and
    // `findByIdAndDelete` no longer appear in this handler. Without adding the
    // aggregate call here, Math.min of an empty list is Infinity and the
    // assertion would pass vacuously — still green, testing nothing.
    const compareAt = fn.indexOf('bcrypt.compare');
    const destructive = ['deleteUserAggregate', 'deletePropertyAssets', 'deleteMany', 'findByIdAndDelete']
      .map((m) => fn.indexOf(m))
      .filter((i) => i !== -1);

    assert.notEqual(compareAt, -1, 'no bcrypt.compare in deleteAccount');
    assert.ok(destructive.length, 'no destructive call found in deleteAccount — has it moved again?');
    assert.ok(
      compareAt < Math.min(...destructive),
      'password check must run before the first destructive operation'
    );
  });

  test('a wrong password returns 401 and deletes nothing', () => {
    assert.match(fn, /INVALID_PASSWORD/);
    assert.match(fn, /status\(401\)/);
  });

  test('the password hash is explicitly selected (req.user has none)', () => {
    // googleId rides along in the same select now — sanitizeUser strips both,
    // and the Google confirmation path below needs to compare against it.
    assert.match(fn, /select\(["']\+password[^"']*["']\)/);
  });

  test('a Google account confirms with a token instead, and only its own', () => {
    // A passwordless account must still be deletable — otherwise Google users
    // cannot close their accounts, which fails both data-rights obligations and
    // App Store review. The equality check is what stops any valid Google token
    // deleting whichever account the session happens to hold.
    assert.match(fn, /GOOGLE_CONFIRMATION_REQUIRED/);
    assert.match(fn, /verifyGoogleIdToken/);
    assert.match(
      fn,
      /identity\.googleId\s*!==\s*accountForAuth\.googleId/,
      'the token must be tied to this account, not merely valid'
    );

    const verifyAt = fn.indexOf('verifyGoogleIdToken');
    const destructive = ['deleteUserAggregate', 'deletePropertyAssets', 'deleteMany', 'findByIdAndDelete']
      .map((m) => fn.indexOf(m))
      .filter((i) => i !== -1);
    assert.ok(
      verifyAt < Math.min(...destructive),
      'the Google check must run before the first destructive operation'
    );
  });

  test('the success message no longer claims all data was deleted', () => {
    assert.doesNotMatch(
      fn,
      /all associated data have been permanently deleted/,
      'six collections are deliberately retained; the message must not overstate'
    );
    assert.match(fn, /retained/i, 'the response should say what is kept');
  });

  test('the deliberately retained collections are still documented', () => {
    // The retention list moved out of deleteAccount into utils/aggregateDelete.js
    // when the cascade was consolidated, and it is now an exported constant
    // rather than a comment. Asserting against the constant is stronger: a
    // comment can drift from the code, USER_CASCADE cannot.
    const aggregate = readFileSync(
      new URL('../utils/aggregateDelete.js', import.meta.url), 'utf8'
    );
    for (const model of ['Lead', 'Agreement', 'TransactionVerification', 'CampaignMember', 'ProjectBooking']) {
      assert.ok(
        USER_CASCADE.retained.includes(model),
        `${model} dropped out of USER_CASCADE.retained — that is a policy change, not a refactor`
      );
      assert.ok(aggregate.includes(model), `${model} lost its TODO in the decision boundary`);
    }
    assert.match(aggregate, /DECISION BOUNDARY/, 'the parked policy note was removed');
  });
});

describe('account deletion is CSRF-guarded', () => {
  test('DELETE /api/users/me is on the Phase 1 list', () => {
    assert.match(
      server,
      /app\.delete\(\s*["']\/api\/users\/me["']\s*,\s*csrfGuard\s*\)/,
      'irreversible deletion must not be reachable by a cross-site request'
    );
  });

  test('the guard is registered before the routers', () => {
    const guardAt = server.indexOf('app.delete("/api/users/me", csrfGuard)');
    const mountAt = server.indexOf('app.use("/api/users"');
    assert.notEqual(guardAt, -1);
    assert.notEqual(mountAt, -1);
    assert.ok(guardAt < mountAt, 'a middleware-only layer must precede its router to run');
  });
});
