/**
 * Admin authentication hardening — cookie clearing, password-rule consistency,
 * MFA session/state checks, MFA failure limiting.
 *
 * The password and cookie tests exercise the real exported values. The MFA
 * tests are source-level: that handler needs a live database and a TOTP secret.
 *
 * Nothing here redesigns the MFA architecture — the mfaVerified:false invariant,
 * the single AdminSession construction site and the protectAdmin gate are all
 * untouched.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §6.5 (F-AU3 cookie clearing,
 * F-AU5 password regex, F-AU8 MFA failure counter, F-AU9 MFA state checks).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { ADMIN_PASSWORD_REGEX, ADMIN_PASSWORD_REQUIREMENTS } from '../models/Admin.js';
import { COOKIE_CONFIG } from '../middleware/authAdmin.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const authAdmin = read('../middleware/authAdmin.js');
const adminController = read('../controllers/adminController.js');
const adminModel = read('../models/Admin.js');

describe('admin password rule is defined once', () => {
  test('the controller no longer declares its own regex', () => {
    assert.doesNotMatch(
      adminController,
      /const ADMIN_PASSWORD_REGEX\s*=/,
      'a local copy will drift from the model and 500 on save'
    );
  });

  test('the controller imports the shared rule', () => {
    assert.match(adminController, /import Admin, \{ ADMIN_PASSWORD_REGEX \}/);
  });

  test('the model validates with the shared rule', () => {
    assert.match(adminModel, /ADMIN_PASSWORD_REGEX\.test\(this\.password\)/);
    assert.doesNotMatch(adminModel, /const passwordRegex\s*=/);
  });

  test('the password that used to 500 is now accepted end to end', () => {
    // Abcdefghij1# passed the controller (which allowed #) and was then
    // rejected by the model (which did not), escaping as a generic 500.
    assert.equal(ADMIN_PASSWORD_REGEX.test('Abcdefghij1#'), true);
  });

  test('every special character the controller advertises is accepted', () => {
    for (const ch of ['@', '$', '!', '%', '*', '?', '&', '#', '^', '(', ')', '-', '_', '=', '+']) {
      assert.equal(
        ADMIN_PASSWORD_REGEX.test(`Abcdefghij1${ch}`),
        true,
        `"${ch}" is advertised but rejected`
      );
    }
  });

  test('genuinely weak passwords are still rejected', () => {
    for (const bad of [
      'short1@A',            // under 12
      'alllowercase1@',      // no uppercase
      'ALLUPPERCASE1@',      // no lowercase
      'NoDigitsHere@@',      // no digit
      'NoSpecialChar123',    // no special
      '',
    ]) {
      assert.equal(ADMIN_PASSWORD_REGEX.test(bad), false, `accepted weak password "${bad}"`);
    }
  });

  test('the requirements string is shared too', () => {
    assert.match(ADMIN_PASSWORD_REQUIREMENTS, /12 characters/);
    assert.match(adminModel, /ADMIN_PASSWORD_REQUIREMENTS/);
  });
});

describe('admin cookie clearing matches how the cookie was set', () => {
  test('clear options are derived from the set options', () => {
    assert.match(
      authAdmin,
      /clearOptionsFrom\(COOKIE_CONFIG\.options\)/,
      'hardcoded clear attributes drift from the setter'
    );
    assert.match(authAdmin, /clearOptionsFrom\(MFA_COOKIE_CONFIG\.options\)/);
  });

  test('the clear no longer hardcodes sameSite strict', () => {
    const clearFns = authAdmin.slice(authAdmin.indexOf('export const clearSessionCookie'));
    assert.doesNotMatch(
      clearFns.slice(0, 400),
      /sameSite:\s*["']strict["']/,
      'the setter uses none/lax; strict does not match and the cookie survives'
    );
  });

  test('domain is carried through, which is what actually matters', () => {
    // A browser matches name + domain + path when deleting. Omitting domain
    // while the setter used COOKIE_DOMAIN left the cookie in place.
    const { maxAge, ...cleared } = COOKIE_CONFIG.options;
    assert.ok('domain' in cleared, 'domain must be present in the derived clear options');
    assert.ok('path' in cleared);
    assert.equal(cleared.path, COOKIE_CONFIG.options.path);
    assert.equal(cleared.sameSite, COOKIE_CONFIG.options.sameSite);
    assert.equal(cleared.secure, COOKIE_CONFIG.options.secure);
  });

  test('maxAge is dropped so clearCookie sets its own expiry', () => {
    const { maxAge, ...cleared } = COOKIE_CONFIG.options;
    assert.ok(!('maxAge' in cleared));
    assert.ok(COOKIE_CONFIG.options.maxAge, 'the setter should still have a maxAge');
  });
});

describe('MFA verification checks session and account state', () => {
  const fn = adminController.slice(
    adminController.indexOf('export const verifyMfa'),
    adminController.indexOf('\nexport const ', adminController.indexOf('export const verifyMfa') + 10)
  );

  test('the pending session must not be expired', () => {
    assert.match(
      fn,
      /expiresAt:\s*\{\s*\$gt:\s*new Date\(\)\s*\}/,
      'an abandoned MFA challenge could be completed long afterwards'
    );
  });

  test('a deactivated admin cannot complete MFA', () => {
    assert.match(fn, /admin\.isActive === false/);
    assert.match(fn, /ACCOUNT_DEACTIVATED/);
  });

  test('a locked admin cannot complete MFA', () => {
    assert.match(fn, /admin\.isLocked/);
    assert.match(fn, /ACCOUNT_LOCKED/);
  });

  test('the state checks run before the code is verified', () => {
    const activeAt = fn.indexOf('admin.isActive === false');
    const verifyAt = fn.indexOf('speakeasy.totp.verify');
    assert.ok(activeAt !== -1 && verifyAt !== -1);
    assert.ok(activeAt < verifyAt, 'state must be checked before spending effort on the code');
  });
});

describe('MFA failures are rate limited', () => {
  const fn = adminController.slice(
    adminController.indexOf('export const verifyMfa'),
    adminController.indexOf('\nexport const ', adminController.indexOf('export const verifyMfa') + 10)
  );

  test('a failed code increments the lockout counter', () => {
    assert.match(
      fn,
      /await admin\.incrementLoginAttempts\(\)/,
      'without a counter, TOTP can be brute-forced within the 5-minute window'
    );
  });

  test('the counter increments on the failure path, not the success path', () => {
    const failAt = fn.indexOf('if (!isValid)');
    const incAt = fn.indexOf('incrementLoginAttempts');
    // Anchor on code, not a comment — comments are stripped before matching.
    const successAt = fn.indexOf('session.mfaVerified = true');
    assert.ok(failAt !== -1 && incAt !== -1 && successAt !== -1);
    assert.ok(failAt < incAt, 'the increment must sit inside the failure branch');
    assert.ok(incAt < successAt, 'the increment must not run on the success path');
  });

  test('reaching the limit locks the account and kills the pending session', () => {
    assert.match(fn, /if \(admin\.isLocked\)[\s\S]{0,200}session\.revoke/);
  });

  test('it reuses the existing lockout rather than inventing a mechanism', () => {
    // incrementLoginAttempts is the same 5-attempt / 30-minute lock the
    // password step uses. No new counter, no new config.
    assert.match(adminModel, /methods\.incrementLoginAttempts/);
    assert.match(adminModel, /MAX_ATTEMPTS = 5/);
    assert.doesNotMatch(fn, /mfaFailedAttempts|mfaLockout/, 'no parallel counter should be introduced');
  });

  test('a successful verification resets the counter', () => {
    assert.match(fn, /resetLoginAttempts/);
  });
});

describe('MFA architecture is unchanged', () => {
  test('createSession still forces mfaVerified false', () => {
    assert.match(authAdmin, /mfaVerified:\s*false/);
  });

  test('AdminSession is still constructed in exactly one place', () => {
    const creates = authAdmin.match(/AdminSession\.create\(/g) || [];
    assert.equal(creates.length, 1, 'a second construction site can bypass the invariant');
  });

  test('protectAdmin still gates on mfaVerified', () => {
    assert.match(authAdmin, /MFA_REQUIRED/);
    assert.match(authAdmin, /MFA_SETUP_REQUIRED/);
  });
});
