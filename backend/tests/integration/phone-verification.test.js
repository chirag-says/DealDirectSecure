/**
 * Just-in-time phone verification, and the owner promotion that rides with it.
 *
 * The SMS OTP used to guard registration. It now guards the five actions that
 * need a real person behind a real number, which promotes it from speed bump to
 * the single control in front of listing, transacting and claiming rewards. So
 * the assertions here are less about the happy path than about the limits:
 * guesses are capped, sends are capped, and a number cannot be stolen from
 * another account.
 *
 * As in auth.test.js, the OTP is read out of the delivered SMS rather than
 * planted in the database, so the code under test does the same work it does in
 * production and "the stored value is not the code" stays a real assertion.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { makeUser, loginAs } from './setup/factories.js';
import { otpSentTo, clearMessages, stopFakeProviders } from './setup/fakeProviders.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); clearMessages(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const User = () => mongoose.model('User');

/** A signed-in account that has NOT proved a phone — the state the gate exists for. */
async function unverifiedSession(overrides = {}) {
  const user = await makeUser({ phoneVerified: false, phone: undefined, ...overrides });
  const cookies = await loginAs(api, user);
  return { user, cookies };
}

const authed = (method, path, cookies) =>
  api[method](path).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies);

/** Drive send-otp and return the code the "handset" received. */
async function requestOtp(cookies, phone) {
  const res = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone });
  return { res, otp: otpSentTo(phone) };
}

// ---------------------------------------------------------------------------

test('the gate', async (t) => {
  await t.test('an unverified account cannot express interest', async () => {
    const { cookies } = await unverifiedSession();
    const res = await authed('post', '/api/properties/interested/000000000000000000000000', cookies).send({});

    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'PHONE_VERIFICATION_REQUIRED');
  });

  await t.test('an unverified account cannot list a property', async () => {
    const { cookies } = await unverifiedSession();
    const res = await authed('post', '/api/properties/add', cookies).send({ title: 'x' });

    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'PHONE_VERIFICATION_REQUIRED');
  });

  await t.test('the agreement routes carry the gate for when they return', () => {
    // Agreements are withdrawn: server.js mounts them only under
    // AGREEMENTS_ENABLED, so there is no live route to drive here and a request
    // would 404 for the wrong reason. Assert the wiring instead, so restoring
    // the feature cannot quietly restore it ungated.
    const src = readFileSync(new URL('../../routes/agreementRoutes.js', import.meta.url), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\r\n]*/g, '');

    for (const route of ['/generate', '/:id/sign']) {
      const block = src.slice(src.indexOf(`"${route}"`));
      assert.match(
        block.slice(0, 200),
        /requirePhoneVerified/,
        `${route} must keep the phone gate when agreements are re-enabled`
      );
    }
  });

  await t.test('browsing and shortlisting stay open', async () => {
    const { cookies } = await unverifiedSession();

    // The gate is meant to be narrow. If it ever spreads to ordinary reads, the
    // whole point of letting people in without a phone is lost.
    const profile = await authed('get', '/api/users/me', cookies).send();
    assert.equal(profile.status, 200);
    assert.equal(profile.body.user.phoneVerified, false);

    const saved = await authed('get', '/api/properties/saved', cookies).send();
    assert.notEqual(saved.status, 403);
  });

  await t.test('the verification endpoints themselves are never gated', async () => {
    // Gating these on being verified would make the gate impossible to pass.
    const { cookies } = await unverifiedSession();
    const res = await authed('get', '/api/users/phone/status', cookies).send();

    assert.equal(res.status, 200);
    assert.equal(res.body.phoneVerified, false);
  });
});

// ---------------------------------------------------------------------------

test('linking a number', async (t) => {
  await t.test('sends a six-digit code and stores it hashed', async () => {
    const { user, cookies } = await unverifiedSession();
    const { res, otp } = await requestOtp(cookies, '9876500001');

    assert.equal(res.status, 200);
    assert.equal(res.body.phoneHint, '01', 'the UI needs a hint, not the number back');
    assert.ok(otp, 'an OTP should have been dispatched');
    assert.match(otp, /^\d{6}$/);

    const stored = await User().findById(user._id).select('+pendingPhone.otp +pendingPhone.phone');
    assert.notEqual(stored.pendingPhone.otp, otp, 'the code must not be stored in clear');
    assert.equal(stored.pendingPhone.phone, '9876500001');
    assert.equal(stored.phoneVerified, false, 'sending a code must not verify anything');
    assert.equal(stored.phone, undefined, 'the number must not land on the account until proved');
  });

  await t.test('the correct code verifies and links the number', async () => {
    const { user, cookies } = await unverifiedSession();
    const { otp } = await requestOtp(cookies, '9876500002');

    const res = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp });

    assert.equal(res.status, 200);
    assert.equal(res.body.user.phoneVerified, true);

    const stored = await User().findById(user._id);
    assert.equal(stored.phone, '9876500002');
    assert.equal(stored.phoneVerified, true);
    assert.ok(stored.phoneVerifiedAt, 'the moment of proof should be recorded');
  });

  await t.test('the gated action succeeds once verified', async () => {
    // This is the whole user-visible promise: bounce, verify, carry on.
    const { cookies } = await unverifiedSession();
    const { otp } = await requestOtp(cookies, '9876500003');
    await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp });

    const res = await authed('post', '/api/properties/interested/000000000000000000000000', cookies).send({});
    assert.notEqual(res.status, 403, 'the gate should be open now');
  });

  await t.test('never exposes the pending OTP or the Google id', async () => {
    const { cookies } = await unverifiedSession();
    await requestOtp(cookies, '9876500004');

    const res = await authed('get', '/api/users/me', cookies).send();
    const body = JSON.stringify(res.body);
    assert.doesNotMatch(body, /pendingPhone/);
    assert.doesNotMatch(body, /googleId/);
  });
});

// ---------------------------------------------------------------------------

test('guessing limits', async (t) => {
  await t.test('five wrong guesses burn the code', async () => {
    const { user, cookies } = await unverifiedSession();
    const { otp } = await requestOtp(cookies, '9876500010');
    const wrong = otp === '111111' ? '222222' : '111111';

    for (let i = 1; i <= 5; i++) {
      const res = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp: wrong });
      assert.equal(res.status, 400, `attempt ${i} should be rejected`);
      assert.equal(res.body.code, 'OTP_INVALID');
      assert.equal(res.body.attemptsRemaining, 5 - i);
    }

    const sixth = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp: wrong });
    assert.equal(sixth.status, 400);
    assert.equal(sixth.body.code, 'OTP_EXPIRED', 'the code should be burned, not merely counted');

    // And the real code is dead too — otherwise five guesses only cost the
    // attacker five guesses, and they could keep going with a fresh request.
    const withReal = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp });
    assert.notEqual(withReal.status, 200, 'a burned code must not verify');

    const stored = await User().findById(user._id);
    assert.equal(stored.phoneVerified, false);
  });

  await t.test('a fresh code restores the guess budget', async () => {
    const { cookies } = await unverifiedSession();
    const first = await requestOtp(cookies, '9876500011');
    const wrong = first.otp === '111111' ? '222222' : '111111';

    await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp: wrong });
    await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp: wrong });

    clearMessages();
    const second = await requestOtp(cookies, '9876500011');
    assert.equal(second.res.status, 200);

    const res = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp: wrong });
    assert.equal(res.body.attemptsRemaining, 4, 'a new code starts a new budget');
  });
});

// ---------------------------------------------------------------------------

test('send limits', async (t) => {
  await t.test('a fourth code inside the window is refused', async () => {
    // Each send costs money at Equence and rings a real handset, so the cap
    // protects the bill and whoever owns the number being dialled.
    const { cookies } = await unverifiedSession();

    for (let i = 0; i < 3; i++) {
      const res = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '9876500020' });
      assert.equal(res.status, 200, `send ${i + 1} should succeed`);
    }

    const fourth = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '9876500020' });
    assert.equal(fourth.status, 429);
    assert.equal(fourth.body.code, 'OTP_SEND_LIMIT');
    assert.ok(fourth.body.retryAfter > 0, 'the client needs to know how long to wait');
  });

  await t.test('the cap is per account, not per IP', async () => {
    // An attacker changes IP at will on a phone network, and an office behind
    // one NAT is not three abusers. Changing IP must not reset the count.
    const { cookies } = await unverifiedSession();

    for (let i = 0; i < 3; i++) {
      await api.post('/api/users/phone/send-otp')
        .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
        .send({ phone: '9876500021' });
    }

    const res = await api.post('/api/users/phone/send-otp')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ phone: '9876500021' });

    assert.equal(res.status, 429, 'a new IP must not buy more sends');
  });

  await t.test('a malformed number never reaches the SMS provider', async () => {
    const { cookies } = await unverifiedSession();
    const res = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '12345' });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_PHONE');
    assert.ok(!otpSentTo('12345'), 'nothing should have been dispatched');
  });
});

// ---------------------------------------------------------------------------

test('a number belongs to one account', async (t) => {
  await t.test('claiming a number another account holds is refused', async () => {
    await makeUser({ phone: '9876500030', phoneVerified: true });
    const { cookies } = await unverifiedSession();

    const res = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '9876500030' });

    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'PHONE_ALREADY_LINKED');
    assert.ok(!otpSentTo('9876500030'), 'the real owner must not be messaged');
  });

  await t.test('a number claimed mid-flow is caught at verification', async () => {
    // The number was free when the code went out. Ten minutes is long enough
    // for someone else to take it, and the unique index would otherwise turn
    // that race into a 500.
    const { cookies } = await unverifiedSession();
    const { otp } = await requestOtp(cookies, '9876500031');

    await makeUser({ phone: '9876500031', phoneVerified: true });

    const res = await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp });
    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'PHONE_ALREADY_LINKED');
  });

  await t.test('re-verifying your own number is a no-op, not an error', async () => {
    const user = await makeUser({ phone: '9876500032', phoneVerified: true });
    const cookies = await loginAs(api, user);

    const res = await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '9876500032' });
    assert.equal(res.status, 200);
    assert.equal(res.body.alreadyVerified, true);
    assert.ok(!otpSentTo('9876500032'), 'no need to spend an SMS');
  });
});

// ---------------------------------------------------------------------------

test('role is earned, not declared', async (t) => {
  await t.test('a verified buyer is promoted on the first listing attempt', async () => {
    const user = await makeUser({ role: 'user', phoneVerified: true });
    const cookies = await loginAs(api, user);
    assert.equal(user.role, 'user', 'precondition');

    // The request itself fails validation further down the chain — there is no
    // multipart body here — but promotion happens in middleware, before that.
    await authed('post', '/api/properties/add', cookies).send({ title: 'anything' });

    const after = await User().findById(user._id);
    assert.equal(after.role, 'owner', 'listing is what makes an account an owner');
  });

  await t.test('an unverified buyer is not promoted', async () => {
    const { user, cookies } = await unverifiedSession({ role: 'user' });

    const res = await authed('post', '/api/properties/add', cookies).send({ title: 'anything' });
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'PHONE_VERIFICATION_REQUIRED');

    const after = await User().findById(user._id);
    assert.equal(after.role, 'user', 'the phone check is what justifies the role');
  });

  await t.test('a role in the request body is ignored', async () => {
    const { user, cookies } = await unverifiedSession({ role: 'user' });

    await authed('post', '/api/users/phone/send-otp', cookies).send({ phone: '9876500040', role: 'owner' });
    const otp = otpSentTo('9876500040');
    await authed('post', '/api/users/phone/verify-otp', cookies).send({ otp, role: 'owner' });

    const after = await User().findById(user._id);
    assert.equal(after.role, 'user', 'the client does not get to name its own role');
  });
});
