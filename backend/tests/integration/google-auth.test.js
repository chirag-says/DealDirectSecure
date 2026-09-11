/**
 * Google Sign-In, and the linking decision that is the whole point of it.
 *
 * WHY THIS FILE NEEDS A MODULE MOCK
 * ---------------------------------
 * Everything else in this suite runs unstubbed. It cannot here: a genuine ID
 * token is an RS256 JWT signed by a Google key the harness cannot hold, and
 * verifying one means a live fetch of Google's JWKS, which the egress block
 * correctly refuses. So `services/googleIdentity.js` — and ONLY that module,
 * which is the single place the codebase decides whether a token is real — is
 * replaced with a controllable stand-in. Every layer after it (the controller,
 * the session, the cookie, the CSRF guard, Mongoose) is the real thing.
 *
 * `mock.module` is still behind --experimental-test-module-mocks, which is why
 * that flag is on the test:integration script. It only enables the API; no
 * other suite is affected by its presence.
 */

import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

/**
 * What the next verifyGoogleIdToken call will return. Tests assign to this
 * before driving a request.
 */
let nextVerification = { ok: false, reason: 'INVALID_TOKEN' };

const googleIdentity = {
  isGoogleAuthConfigured: () => true,
  verifyGoogleIdToken: async () => nextVerification,
};

// Must precede the server.js import inside getApp(), or the real module is
// already bound into the controller.
mock.module('../../services/googleIdentity.js', { namedExports: googleIdentity });

const { request, uniqueClientIp, cookiesFrom } = await import('./setup/app.js');
const { stopTestDatabase, truncateAll } = await import('./setup/db.js');
const { makeUser, loginAs, TEST_PASSWORD } = await import('./setup/factories.js');
const { clearMessages, stopFakeProviders, otpSentTo } = await import('./setup/fakeProviders.js');

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => {
  await truncateAll();
  clearMessages();
  nextVerification = { ok: false, reason: 'INVALID_TOKEN' };
});
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const User = () => mongoose.model('User');

/** Arrange a successful Google verification for the given identity. */
const googleReturns = (identity) => {
  nextVerification = {
    ok: true,
    identity: { googleId: 'sub-default', name: 'Google Person', picture: null, ...identity },
  };
};

const post = (path, body, cookies) => {
  const req = api.post(path).set('X-Forwarded-For', uniqueClientIp());
  if (cookies) req.set('Cookie', cookies);
  return req.send(body);
};

const signIn = (body = { idToken: 'whatever' }) => post('/api/users/auth/google', body);

/** True when the response actually established a session. */
const issuedSession = (res) =>
  (res.headers['set-cookie'] || []).some((c) => c.startsWith('user_session='));

// ---------------------------------------------------------------------------

test('a token is never taken on trust', async (t) => {
  await t.test('an unverifiable token is refused', async () => {
    nextVerification = { ok: false, reason: 'INVALID_TOKEN' };
    const res = await signIn();

    assert.equal(res.status, 401);
    assert.equal(res.body.code, 'GOOGLE_INVALID_TOKEN');
    assert.equal(await User().countDocuments(), 0, 'no account may be created from a bad token');
  });

  await t.test('an unconfirmed Google email is refused', async () => {
    // Google can assert an identity whose inbox it has not checked. The entire
    // linking decision leans on Google having checked, so this cannot pass.
    nextVerification = { ok: false, reason: 'EMAIL_NOT_VERIFIED' };
    const res = await signIn();

    assert.equal(res.status, 401);
    assert.equal(res.body.code, 'GOOGLE_EMAIL_NOT_VERIFIED');
  });

  await t.test('an email in the request body is ignored', async () => {
    // The only email that counts is the one inside the verified token.
    googleReturns({ googleId: 'sub-body', email: 'real@example.com' });
    const res = await signIn({ idToken: 'x', email: 'attacker@example.com' });

    assert.equal(res.status, 201);
    assert.ok(await User().findOne({ email: 'real@example.com' }));
    assert.equal(await User().countDocuments({ email: 'attacker@example.com' }), 0);
  });
});

// ---------------------------------------------------------------------------

test('a brand new Google account', async (t) => {
  await t.test('is created, signed in, and owes a phone number', async () => {
    googleReturns({ googleId: 'sub-new', email: 'newcomer@example.com', name: 'New Comer' });
    const res = await signIn();

    assert.equal(res.status, 201);
    assert.ok(issuedSession(res), 'a session should be established');
    assert.equal(res.body.user.emailVerified, true, 'Google did check the inbox');
    assert.equal(res.body.user.phoneVerified, false, 'nothing has checked a phone');

    const user = await User().findOne({ email: 'newcomer@example.com' }).select('+password +googleId');
    assert.equal(user.googleId, 'sub-new');
    assert.equal(user.password, undefined, 'a Google account has no password');
    assert.equal(user.phone, undefined, 'and no phone until it needs one');
    assert.equal(user.role, 'user', 'role is earned later, not chosen at signup');
  });

  await t.test('gets a rewards wallet and a referral code like any other signup', async () => {
    googleReturns({ googleId: 'sub-hooks', email: 'hooks@example.com' });
    await signIn();

    const user = await User().findOne({ email: 'hooks@example.com' });
    assert.ok(user.referralCode, 'the post-registration hooks should have run');
    assert.ok(await mongoose.model('Reward').findOne({ user: user._id }), 'wallet should exist');
  });

  await t.test('still cannot perform a gated action', async () => {
    googleReturns({ googleId: 'sub-gated', email: 'gated@example.com' });
    const res = await signIn();
    const cookies = cookiesFrom(res);

    const gated = await post('/api/properties/interested/000000000000000000000000', {}, cookies);
    assert.equal(gated.status, 403);
    assert.equal(gated.body.code, 'PHONE_VERIFICATION_REQUIRED');
  });

  await t.test('can verify a phone and then proceed', async () => {
    googleReturns({ googleId: 'sub-flow', email: 'flow@example.com' });
    const cookies = cookiesFrom(await signIn());

    await post('/api/users/phone/send-otp', { phone: '9876511111' }, cookies);
    const verify = await post('/api/users/phone/verify-otp', { otp: otpSentTo('9876511111') }, cookies);

    assert.equal(verify.status, 200);
    assert.equal(verify.body.user.phoneVerified, true);

    const gated = await post('/api/properties/interested/000000000000000000000000', {}, cookies);
    assert.notEqual(gated.status, 403);
  });
});

// ---------------------------------------------------------------------------

test('a returning Google account', async (t) => {
  await t.test('is matched by sub, not by email', async () => {
    // A Workspace admin can hand someone else the address. The sub belongs to
    // the Google account for its lifetime, so it is the only safe key.
    googleReturns({ googleId: 'sub-stable', email: 'before@example.com' });
    const first = await signIn();
    const id = first.body.user._id;

    googleReturns({ googleId: 'sub-stable', email: 'after@example.com' });
    const second = await signIn();

    assert.equal(second.status, 200, 'this is a sign-in, not a signup');
    assert.equal(second.body.user._id, id, 'the same person, not a second account');
    assert.equal(second.body.user.email, 'after@example.com', 'Google is authoritative for the address');
    assert.equal(await User().countDocuments(), 1);
  });

  await t.test('keeps its old address if the new one is taken locally', async () => {
    await makeUser({ email: 'occupied@example.com' });
    googleReturns({ googleId: 'sub-collide', email: 'mine@example.com' });
    await signIn();

    googleReturns({ googleId: 'sub-collide', email: 'occupied@example.com' });
    const res = await signIn();

    assert.equal(res.status, 200);
    assert.equal(res.body.user.email, 'mine@example.com', 'better stale than colliding');
    assert.equal(await User().countDocuments(), 2, 'and certainly not merged');
  });

  await t.test('a blocked account is refused', async () => {
    googleReturns({ googleId: 'sub-blocked', email: 'blocked@example.com' });
    await signIn();
    await User().updateOne({ email: 'blocked@example.com' }, { $set: { isBlocked: true } });

    const res = await signIn();
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'ACCOUNT_BLOCKED');
    assert.ok(!issuedSession(res));
  });
});

// ---------------------------------------------------------------------------

test('an existing password account is never absorbed silently', async (t) => {
  // The pre-hijacking case. Registration in this codebase never verifies email,
  // so an account under someone else's Gmail can be created by anyone. Silent
  // merge would drop the real owner into the squatter's account, password and
  // all, with nothing visible happening.

  await t.test('sign-in stops with a link request and issues no session', async () => {
    await makeUser({ email: 'existing@example.com' });
    googleReturns({ googleId: 'sub-link', email: 'existing@example.com' });

    const res = await signIn();

    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'GOOGLE_LINK_REQUIRED');
    assert.ok(!issuedSession(res), 'this is the whole point: no session without the password');

    const user = await User().findOne({ email: 'existing@example.com' }).select('+googleId');
    assert.equal(user.googleId, undefined, 'nothing is linked yet');
  });

  await t.test('the correct password links the accounts and signs in', async () => {
    const user = await makeUser({ email: 'linkme@example.com' });
    googleReturns({ googleId: 'sub-linked', email: 'linkme@example.com' });

    const res = await post('/api/users/auth/google/link', { idToken: 'x', password: TEST_PASSWORD });

    assert.equal(res.status, 200);
    assert.ok(issuedSession(res));

    const after = await User().findById(user._id).select('+googleId +password');
    assert.equal(after.googleId, 'sub-linked');
    assert.equal(after.emailVerified, true, 'Google has now actually checked the inbox');
    assert.ok(after.password, 'the password survives; both doors work from here');
  });

  await t.test('a wrong password links nothing', async () => {
    const user = await makeUser({ email: 'guessme@example.com' });
    googleReturns({ googleId: 'sub-guess', email: 'guessme@example.com' });

    const res = await post('/api/users/auth/google/link', { idToken: 'x', password: 'WrongPassw0rd!' });

    assert.equal(res.status, 401);
    assert.ok(!issuedSession(res));

    const after = await User().findById(user._id).select('+googleId');
    assert.equal(after.googleId, undefined);
  });

  await t.test('wrong passwords feed the same lockout as password login', async () => {
    // Otherwise this endpoint is an unthrottled oracle for the very credential
    // loginUser rate-limits.
    const user = await makeUser({ email: 'lockme@example.com' });
    googleReturns({ googleId: 'sub-lock', email: 'lockme@example.com' });

    for (let i = 0; i < 5; i++) {
      await post('/api/users/auth/google/link', { idToken: 'x', password: 'WrongPassw0rd!' });
    }

    const after = await User().findById(user._id).select('+security.lockoutUntil');
    assert.ok(after.security.lockoutUntil > new Date(), 'the account should be locked out');

    const res = await post('/api/users/auth/google/link', { idToken: 'x', password: TEST_PASSWORD });
    assert.equal(res.status, 423, 'even the right password waits out the lockout');
  });

  await t.test('linking does not reveal whether an email is registered', async () => {
    googleReturns({ googleId: 'sub-enum', email: 'nobody@example.com' });
    const res = await post('/api/users/auth/google/link', { idToken: 'x', password: TEST_PASSWORD });

    assert.equal(res.status, 401);
    assert.equal(res.body.message, 'Invalid password', 'same answer as a wrong password');
  });

  await t.test('a second Google account cannot take over a linked one', async () => {
    const user = await makeUser({ email: 'taken@example.com' });
    await User().updateOne({ _id: user._id }, { $set: { googleId: 'sub-first' } });

    googleReturns({ googleId: 'sub-second', email: 'taken@example.com' });
    const res = await post('/api/users/auth/google/link', { idToken: 'x', password: TEST_PASSWORD });

    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'GOOGLE_ALREADY_LINKED');
  });
});

// ---------------------------------------------------------------------------

test('the two doors stay independent', async (t) => {
  await t.test('a Google-only account cannot be password-logged-into', async () => {
    googleReturns({ googleId: 'sub-nopass', email: 'nopass@example.com' });
    await signIn();

    const res = await post('/api/users/login', { email: 'nopass@example.com', password: TEST_PASSWORD });

    // 401, not 500. bcrypt.compare against an absent hash throws, and letting
    // that surface would both crash and leak "this email exists but has no
    // password" through the status code alone.
    assert.equal(res.status, 401, 'there is no password to match');
    assert.equal(res.body.code, 'USE_GOOGLE_SIGNIN', 'and it should say which door to use');
  });

  await t.test('a Google-only account gets a clear answer on change-password', async () => {
    googleReturns({ googleId: 'sub-chpw', email: 'chpw@example.com' });
    const cookies = cookiesFrom(await signIn());

    const res = await api.put('/api/users/change-password')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'AnotherPassw0rd!' });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'NO_PASSWORD_SET');
  });

  await t.test('password reset explains itself when there is no number to text', async () => {
    googleReturns({ googleId: 'sub-reset', email: 'reset@example.com' });
    await signIn();

    const res = await post('/api/users/forgot-password', { email: 'reset@example.com' });

    assert.equal(res.status, 400, 'a user-state problem is not a server error');
    assert.equal(res.body.code, 'NO_PHONE_ON_ACCOUNT');
  });
});

// ---------------------------------------------------------------------------

test('a Google account can still be deleted', async (t) => {
  // Requiring a password would leave these accounts undeletable, which is both
  // a data-rights failure and an App Store rejection.

  await t.test('a stale session alone is not enough', async () => {
    googleReturns({ googleId: 'sub-del1', email: 'del1@example.com' });
    const cookies = cookiesFrom(await signIn());

    const res = await api.delete('/api/users/me')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies).send({});

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'GOOGLE_CONFIRMATION_REQUIRED');
    assert.ok(await User().findOne({ email: 'del1@example.com' }), 'still there');
  });

  await t.test('a fresh Google token for the same account deletes it', async () => {
    googleReturns({ googleId: 'sub-del2', email: 'del2@example.com' });
    const cookies = cookiesFrom(await signIn());

    const res = await api.delete('/api/users/me')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ idToken: 'fresh' });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await User().countDocuments({ email: 'del2@example.com' }), 0);
  });

  await t.test('a token for a different Google account deletes nothing', async () => {
    googleReturns({ googleId: 'sub-del3', email: 'del3@example.com' });
    const cookies = cookiesFrom(await signIn());

    // Valid token, wrong person. Without the googleId equality check this would
    // delete whichever account the session happened to hold.
    googleReturns({ googleId: 'sub-someone-else', email: 'other@example.com' });
    const res = await api.delete('/api/users/me')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ idToken: 'fresh' });

    assert.equal(res.status, 401);
    assert.equal(res.body.code, 'INVALID_GOOGLE_CONFIRMATION');
    assert.ok(await User().findOne({ email: 'del3@example.com' }), 'still there');
  });

  await t.test('a password account still needs its password', async () => {
    const user = await makeUser({ email: 'delpw@example.com' });
    const cookies = await loginAs(api, user);

    const withToken = await api.delete('/api/users/me')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ idToken: 'fresh' });
    assert.equal(withToken.status, 400, 'a Google token must not substitute for a set password');
    assert.equal(withToken.body.code, 'PASSWORD_REQUIRED');
  });
});

// ---------------------------------------------------------------------------

test('both doors keep working after a link', async (t) => {
  await t.test('a linked account still logs in with its password', async () => {
    const user = await makeUser({ email: 'both@example.com' });
    googleReturns({ googleId: 'sub-both', email: 'both@example.com' });
    await post('/api/users/auth/google/link', { idToken: 'x', password: TEST_PASSWORD });

    const cookies = await loginAs(api, user);
    assert.ok(cookies, 'the original door is still open');
  });

  await t.test('a Google user can be given a password without breaking the model', async () => {
    // Guards the conditional `required` on password: it is scoped to isNew, so
    // ordinary saves on a Google account must not start demanding one.
    googleReturns({ googleId: 'sub-save', email: 'save@example.com' });
    await signIn();

    const user = await User().findOne({ email: 'save@example.com' });
    user.bio = 'edited without selecting password or googleId';
    await assert.doesNotReject(user.save(), 'a routine save must not trip password validation');

    user.password = await bcrypt.hash(TEST_PASSWORD, 12);
    await assert.doesNotReject(user.save());
  });
});
