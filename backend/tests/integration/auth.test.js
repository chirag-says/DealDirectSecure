/**
 * Suite 1: Authentication.
 *
 * Drives the real registration, OTP verification, login, session and logout
 * endpoints through the full middleware chain. Nothing is stubbed, so a
 * regression in a validator, a cookie flag, or the session lookup shows up here
 * rather than in production.
 *
 * The OTP is read out of the delivered message, not planted in the database.
 * The harness points the SMS client at a loopback server (see
 * setup/fakeProviders.js), so registration follows the code path it follows in
 * production (build the request, send it, parse the reply), and the test
 * learns the code the same way a user does. That keeps the assertion "the
 * stored value is not the OTP" meaningful, because nothing here recomputes the
 * stored hash.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { makeUser, loginAs, TEST_PASSWORD } from './setup/factories.js';
import {
  otpSentTo, lastMessageTo, clearMessages, stopFakeProviders,
} from './setup/fakeProviders.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); clearMessages(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const post = (path, body) =>
  api.post(path).set('X-Forwarded-For', uniqueClientIp()).send(body);

const validRegistration = (n) => ({
  name: `Test Registrant ${n}`,
  email: `test-registrant-${n}@example.com`,
  password: TEST_PASSWORD,
  phone: `98765${String(10000 + n).slice(-5)}`,
});

// ---------------------------------------------------------------------------

test('registration', async (t) => {
  await t.test('creates an unverified user with a hashed password', async () => {
    const body = validRegistration(1);
    const res = await post('/api/users/register', body);

    assert.ok(res.status === 200 || res.status === 201, `got ${res.status}: ${JSON.stringify(res.body)}`);

    const user = await mongoose.model('User').findOne({ email: body.email }).select('+password');
    assert.ok(user, 'user should exist');
    assert.equal(user.isVerified, false, 'a new registration must not be pre-verified');
    assert.notEqual(user.password, body.password, 'password must not be stored in clear');
    assert.match(user.password, /^\$2[aby]\$/, 'password must be a bcrypt hash');
  });

  await t.test('sends the OTP to the registered number and nowhere else', async () => {
    const body = validRegistration(2);
    await post('/api/users/register', body);

    const msg = lastMessageTo(body.phone);
    assert.ok(msg, 'an OTP message should have been dispatched');
    assert.match(String(msg.text), /\b\d{6}\b/, 'the message should carry a six-digit code');
    assert.ok(String(msg.to).endsWith(body.phone.slice(-10)));
  });

  await t.test('does not store the OTP in recoverable form', async () => {
    const body = validRegistration(3);
    await post('/api/users/register', body);

    const sent = otpSentTo(body.phone);
    assert.ok(sent, 'precondition: an OTP was sent');

    // `otp` is select:false (userModel.js:98), so an ordinary read does not
    // return it at all, which is itself the first line of defence.
    const defaultRead = await mongoose.model('User').findOne({ email: body.email });
    assert.equal(defaultRead.otp, undefined, 'the OTP must not come back on a normal query');

    const user = await mongoose.model('User').findOne({ email: body.email }).select('+otp');
    assert.ok(user.otp, 'an OTP hash should be stored');
    assert.equal(user.otp.length, 64, 'stored OTP should be a sha256 hex digest, not 6 digits');
    assert.notEqual(user.otp, sent, 'the stored value must not be the OTP itself');
  });

  await t.test('does not return the OTP in the API response', async () => {
    const body = validRegistration(4);
    const res = await post('/api/users/register', body);
    const sent = otpSentTo(body.phone);
    assert.ok(sent);
    assert.ok(
      !JSON.stringify(res.body).includes(sent),
      'the response body must not echo the OTP'
    );
  });

  await t.test('rejects a password that fails the strength policy', async () => {
    const res = await post('/api/users/register', { ...validRegistration(5), password: 'password' });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /password/i);
    assert.equal(lastMessageTo(validRegistration(5).phone), null, 'no OTP for a rejected registration');
  });

  await t.test('rejects a malformed phone number', async () => {
    const res = await post('/api/users/register', { ...validRegistration(6), phone: '12345' });
    assert.equal(res.status, 400);
  });

  await t.test('rejects a missing required field', async () => {
    const { phone, ...noPhone } = validRegistration(7);
    const res = await post('/api/users/register', noPhone);
    assert.equal(res.status, 400);
  });

  await t.test('refuses to re-register a verified email', async () => {
    const existing = await makeUser();
    const res = await post('/api/users/register', {
      ...validRegistration(8),
      email: existing.email,
    });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /already registered/i);
  });
});

// ---------------------------------------------------------------------------

test('OTP verification', async (t) => {
  await t.test('the OTP that was actually delivered verifies the account', async () => {
    const body = validRegistration(10);
    await post('/api/users/register', body);

    const otp = otpSentTo(body.phone);
    assert.ok(otp, 'precondition: an OTP was delivered');

    const res = await post('/api/users/verify-otp', { email: body.email, otp });
    // 201, not 200: verify-otp completes the registration and reports a
    // creation (userController.js:400). Register itself returns 200.
    assert.equal(res.status, 201, JSON.stringify(res.body));

    const user = await mongoose.model('User').findOne({ email: body.email });
    assert.equal(user.isVerified, true);
  });

  await t.test('a wrong OTP does not verify the account', async () => {
    const body = validRegistration(11);
    await post('/api/users/register', body);

    const otp = otpSentTo(body.phone);
    const wrong = String((Number(otp) + 1) % 1000000).padStart(6, '0');

    const res = await post('/api/users/verify-otp', { email: body.email, otp: wrong });
    assert.notEqual(res.status, 200);

    const user = await mongoose.model('User').findOne({ email: body.email });
    assert.equal(user.isVerified, false);
  });

  await t.test('an expired OTP is refused even though the digits are right', async () => {
    const body = validRegistration(12);
    await post('/api/users/register', body);
    const otp = otpSentTo(body.phone);

    await mongoose.model('User').updateOne(
      { email: body.email },
      { otpExpires: new Date(Date.now() - 1000) }
    );

    const res = await post('/api/users/verify-otp', { email: body.email, otp });
    assert.notEqual(res.status, 200);

    const user = await mongoose.model('User').findOne({ email: body.email });
    assert.equal(user.isVerified, false);
  });

  await t.test('an OTP issued for one account cannot verify another', async () => {
    const first = validRegistration(13);
    const second = validRegistration(14);
    await post('/api/users/register', first);
    await post('/api/users/register', second);

    const firstOtp = otpSentTo(first.phone);
    const secondOtp = otpSentTo(second.phone);
    assert.notEqual(firstOtp, secondOtp, 'each registration must get its own code');

    const res = await post('/api/users/verify-otp', { email: second.email, otp: firstOtp });
    assert.notEqual(res.status, 200);

    const user = await mongoose.model('User').findOne({ email: second.email });
    assert.equal(user.isVerified, false);
  });
});

// ---------------------------------------------------------------------------

test('login', async (t) => {
  await t.test('succeeds with correct credentials and issues a session cookie', async () => {
    const user = await makeUser();
    const res = await post('/api/users/login', { email: user.email, password: TEST_PASSWORD });

    assert.equal(res.status, 200, JSON.stringify(res.body));

    const setCookie = res.headers['set-cookie'] || [];
    const session = setCookie.find((c) => c.startsWith('user_session='));
    assert.ok(session, 'login must set the user_session cookie');
    assert.match(session, /HttpOnly/i, 'the session cookie must be HttpOnly');
    assert.match(session, /SameSite/i, 'the session cookie must declare SameSite');
  });

  await t.test('never returns the password hash in the response body', async () => {
    const user = await makeUser();
    const res = await post('/api/users/login', { email: user.email, password: TEST_PASSWORD });
    assert.equal(res.status, 200);
    assert.ok(!JSON.stringify(res.body).includes('$2'), 'response must not carry a bcrypt hash');
    assert.equal(res.body?.user?.password, undefined);
  });

  await t.test('rejects a wrong password without issuing a session', async () => {
    const user = await makeUser();
    const res = await post('/api/users/login', { email: user.email, password: 'WrongPassw0rd!23' });

    assert.equal(res.status, 401);
    const setCookie = res.headers['set-cookie'] || [];
    assert.ok(
      !setCookie.some((c) => c.startsWith('user_session=') && !c.includes('user_session=;')),
      'a failed login must not issue a session cookie'
    );
  });

  await t.test('gives the same answer for an unknown email as for a wrong password', async () => {
    // Both must be 401 with an identical message, or login becomes an account
    // enumeration oracle.
    const user = await makeUser();
    const wrongPw = await post('/api/users/login', { email: user.email, password: 'WrongPassw0rd!23' });
    const unknown = await post('/api/users/login', { email: 'test-nobody@example.com', password: TEST_PASSWORD });

    assert.equal(wrongPw.status, unknown.status);
    assert.equal(wrongPw.body.message, unknown.body.message);
  });

  await t.test('refuses an unverified account', async () => {
    const user = await makeUser({ isVerified: false });
    const res = await post('/api/users/login', { email: user.email, password: TEST_PASSWORD });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'EMAIL_NOT_VERIFIED');
  });

  await t.test('refuses a blocked account', async () => {
    const user = await makeUser({ isBlocked: true, blockReason: 'synthetic test block' });
    const res = await post('/api/users/login', { email: user.email, password: TEST_PASSWORD });
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'ACCOUNT_BLOCKED');
  });

  await t.test('is case-insensitive on the email', async () => {
    const user = await makeUser();
    const res = await post('/api/users/login', {
      email: user.email.toUpperCase(),
      password: TEST_PASSWORD,
    });
    assert.equal(res.status, 200);
  });
});

// ---------------------------------------------------------------------------

test('session lifecycle', async (t) => {
  await t.test('a protected route rejects an anonymous request', async () => {
    const res = await api.get('/api/users/profile').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 401);
  });

  await t.test('a protected route accepts a live session and returns that user', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);

    const res = await api
      .get('/api/users/profile')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies);

    assert.equal(res.status, 200, JSON.stringify(res.body));
    const payload = JSON.stringify(res.body);
    assert.ok(payload.includes(user.email), 'profile must be the logged-in user');
    assert.ok(!payload.includes('$2'), 'profile must not leak the password hash');
  });

  await t.test('a forged session cookie is rejected', async () => {
    const res = await api
      .get('/api/users/profile')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', ['user_session=not-a-real-token']);
    assert.equal(res.status, 401);
  });

  await t.test('logout invalidates the session server-side', async () => {
    const user = await makeUser();
    const cookies = await loginAs(api, user);
    const ip = uniqueClientIp();

    const before = await api.get('/api/users/profile').set('X-Forwarded-For', ip).set('Cookie', cookies);
    assert.equal(before.status, 200);

    const out = await api.post('/api/users/logout').set('X-Forwarded-For', ip).set('Cookie', cookies);
    assert.equal(out.status, 200, JSON.stringify(out.body));

    // Replay the ORIGINAL cookie. If the session were only cleared in the
    // browser, this would still succeed, which is the bug this asserts against.
    const after = await api.get('/api/users/profile').set('X-Forwarded-For', ip).set('Cookie', cookies);
    assert.equal(after.status, 401, 'the session token must stop working after logout');
  });

  await t.test('one user\'s session does not grant access as another', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const cookiesA = await loginAs(api, a);

    const res = await api
      .get('/api/users/profile')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookiesA);

    assert.equal(res.status, 200);
    assert.ok(!JSON.stringify(res.body).includes(b.email));
  });
});

// ---------------------------------------------------------------------------

test('the auth rate limiter actually engages', async (t) => {
  await t.test('repeated login attempts from one IP are eventually refused', async () => {
    // Deliberately reuses a single IP, everywhere else in the suite each
    // request gets its own so this limit is not hit by accident.
    const ip = uniqueClientIp();
    const statuses = [];

    for (let i = 0; i < 8; i += 1) {
      const res = await api
        .post('/api/users/login')
        .set('X-Forwarded-For', ip)
        .send({ email: `test-throttle-${i}@example.com`, password: TEST_PASSWORD });
      statuses.push(res.status);
    }

    assert.ok(
      statuses.includes(429),
      `expected a 429 within 8 attempts from one IP, saw ${statuses.join(',')}`
    );
  });

  await t.test('a different IP is unaffected by that limit', async () => {
    const user = await makeUser();
    const res = await post('/api/users/login', { email: user.email, password: TEST_PASSWORD });
    assert.equal(res.status, 200, 'the limiter must be per-IP, not global');
  });
});
