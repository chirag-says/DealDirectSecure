/**
 * Suite 19: the scope of the CSRF cookie middleware (Phase 4.10).
 *
 * TWO SEPARATE MECHANISMS, and the distinction is the whole point of this file.
 *
 *   setCsrfToken  ISSUES the cookie. Mounted globally at server.js:685, so it
 *                 ran on every request — including static assets under
 *                 /uploads, which is mounted at :827 with
 *                 `Cache-Control: public, max-age=86400`.
 *
 *   requireCsrf   ENFORCES the double submit. Applied to a named list of 13
 *                 state-changing routes, and it already skips GET/HEAD/OPTIONS
 *                 and requests with no Origin header.
 *
 * The defect was in the first, not the second. A response carrying `Set-Cookie`
 * is not cacheable by a shared cache, so issuing the token on every static
 * asset defeated the caching that mount was explicitly configured for. Nothing
 * about enforcement changes here.
 *
 * WHY THE SKIP RULE IS NARROW. It would be tempting to skip all safe methods,
 * and that would break CSRF for real users. The double-submit pattern needs the
 * cookie present BEFORE the first mutating request, and `fetchCsrfToken` has
 * zero callers in either client — nothing bootstraps the token explicitly. It
 * is issued implicitly by whatever request happens first, which is always a GET.
 * Skipping GETs would leave a fresh session with no cookie and the first
 * mutation would 403.
 *
 * So the rule is: skip static assets and the monitoring endpoint. Nothing else.
 * `/ping` and `/debug-startup` are registered before the middleware and never
 * received the cookie anyway.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { ownerWithSession, TEST_PASSWORD } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/** An origin on the development whitelist, so requireCsrf engages. */
const ORIGIN = 'http://localhost:3000';

const setCookieOf = (res) => (res.headers['set-cookie'] || []).join('; ');
const issuesCsrfCookie = (res) => /csrf_token=/.test(setCookieOf(res));

/** Fetch a live token and the cookie string that carries it. */
async function csrfPair() {
  const res = await api.get('/api/csrf-token').set('X-Forwarded-For', uniqueClientIp());
  const cookie = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
  const token = decodeURIComponent((cookie.match(/csrf_token=([^;]+)/) || [])[1] || '');
  return { cookie, token };
}

// ---------------------------------------------------------------------------

test('the cookie is still issued everywhere it is needed', async (t) => {
  await t.test('an API read issues it', async () => {
    // This is how the token is actually bootstrapped: implicitly, on whatever
    // request the browser makes first. Nothing calls fetchCsrfToken.
    const res = await api.get('/api/categories/list-category').set('X-Forwarded-For', uniqueClientIp());
    assert.ok(issuesCsrfCookie(res), 'a fresh session would have no token before its first mutation');
  });

  await t.test('the dedicated endpoint issues it', async () => {
    const res = await api.get('/api/csrf-token').set('X-Forwarded-For', uniqueClientIp());
    assert.ok(issuesCsrfCookie(res));
  });

  await t.test('an authenticated API read issues it', async () => {
    const { cookies } = await ownerWithSession(api);
    const res = await api.get('/api/properties/my-properties')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies);
    assert.ok(issuesCsrfCookie(res));
  });

  await t.test('a POST issues it too', async () => {
    const res = await api.post('/api/users/login')
      .set('X-Forwarded-For', uniqueClientIp())
      .send({ email: 'nobody@example.com', password: 'wrong' });
    assert.ok(issuesCsrfCookie(res), 'the cookie must survive the login round trip');
  });
});

// ---------------------------------------------------------------------------

test('the cookie is NOT issued where it can serve no purpose', async (t) => {
  await t.test('static assets under /uploads', async () => {
    // The measurable one. This mount sets Cache-Control: public, max-age=86400,
    // and Set-Cookie makes a response uncacheable by any shared cache.
    const res = await api.get('/uploads/does-not-exist.jpg').set('X-Forwarded-For', uniqueClientIp());
    assert.ok(!issuesCsrfCookie(res), 'Set-Cookie on a static asset defeats its own Cache-Control');
  });

  await t.test('the health endpoint', async () => {
    // Hit by uptime checkers, not browsers. Never precedes a mutation.
    const res = await api.get('/health').set('X-Forwarded-For', uniqueClientIp());
    assert.ok(!issuesCsrfCookie(res));
  });

  await t.test('and /health still answers', async () => {
    const res = await api.get('/health').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200, 'the skip must not change what the endpoint does');
  });
});

// ---------------------------------------------------------------------------

test('enforcement is unchanged — the double submit still holds', async (t) => {
  const guarded = () => api.delete('/api/users/me').set('X-Forwarded-For', uniqueClientIp());

  await t.test('a browser request with neither cookie nor header is refused', async () => {
    const res = await guarded().set('Origin', ORIGIN).send({ password: TEST_PASSWORD });
    assert.equal(res.status, 403, JSON.stringify(res.body).slice(0, 160));
    assert.match(res.body.code || '', /CSRF/);
  });

  await t.test('cookie without header is refused', async () => {
    const { cookie } = await csrfPair();
    const res = await guarded().set('Origin', ORIGIN).set('Cookie', cookie).send({ password: TEST_PASSWORD });
    assert.equal(res.status, 403, JSON.stringify(res.body).slice(0, 160));
  });

  await t.test('header that does not match the cookie is refused', async () => {
    const { cookie } = await csrfPair();
    const res = await guarded().set('Origin', ORIGIN).set('Cookie', cookie)
      .set('X-CSRF-Token', 'a-token-from-somewhere-else').send({ password: TEST_PASSWORD });
    assert.equal(res.status, 403, JSON.stringify(res.body).slice(0, 160));
  });

  await t.test('matching header and cookie passes CSRF and reaches auth', async () => {
    // 401 rather than 403 is the proof: the request got past CSRF and was
    // rejected by authentication instead.
    const { cookie, token } = await csrfPair();
    const res = await guarded().set('Origin', ORIGIN).set('Cookie', cookie)
      .set('X-CSRF-Token', token).send({ password: TEST_PASSWORD });
    assert.equal(res.status, 401, JSON.stringify(res.body).slice(0, 160));
  });

  await t.test('an untrusted origin never reaches the token check', async () => {
    // CORS is the OUTER layer and rejects first, with CORS_REJECTED — the
    // requireCsrf origin whitelist behind it never runs. That is correct
    // defence in depth, and worth pinning: if CORS ever stopped rejecting,
    // this would start returning CSRF_ORIGIN_REJECTED instead of passing, and
    // the change in which layer caught it would be visible here.
    const { cookie, token } = await csrfPair();
    const res = await guarded().set('Origin', 'https://evil.example.com')
      .set('Cookie', cookie).set('X-CSRF-Token', token).send({ password: TEST_PASSWORD });

    assert.equal(res.status, 403);
    assert.ok(
      ['CORS_REJECTED', 'CSRF_ORIGIN_REJECTED'].includes(res.body.code),
      `a foreign origin was neither CORS- nor CSRF-rejected: ${JSON.stringify(res.body).slice(0, 140)}`
    );
  });
});

// ---------------------------------------------------------------------------

test('no state-changing route became accidentally exempt', async (t) => {
  // Every route on the csrfGuard list, driven as a browser would drive it.
  // A route that stops refusing here has lost its protection.
  const GUARDED = [
    ['post', '/api/rewards/admin/adjust-points'],
    ['post', '/api/properties/add'],
    ['put', '/api/properties/my-properties/000000000000000000000000'],
    ['post', '/api/properties/admin/add'],
    ['put', '/api/properties/edit/000000000000000000000000'],
    ['post', '/api/properties/interested/000000000000000000000000'],
    ['post', '/api/properties/000000000000000000000000/report'],
    ['post', '/api/campaigns/000000000000000000000000/join'],
    ['post', '/api/campaigns/000000000000000000000000/exit'],
    ['post', '/api/contact'],
    ['post', '/api/chat/message/send'],
    ['post', '/api/chat/conversation/start'],
    ['delete', '/api/users/me'],
    // Project bookings — the path that takes real money over UPI. Added in
    // Stage 2; they were the only money-adjacent user routes left off the list,
    // which already covered campaign join for exactly the same reason.
    ['post', '/api/bookings'],
    ['post', '/api/bookings/000000000000000000000000/payment'],
    ['post', '/api/bookings/000000000000000000000000/cancel'],
    // Auth unification. The Google routes run before a session exists, which is
    // the reason they are guarded rather than a reason to skip them: login CSRF
    // drops the victim into the attacker's account, and everything they do next
    // happens there. The phone routes spend real money on an SMS and, once
    // passed, unlock listing, transacting and reward claims.
    ['post', '/api/users/auth/google'],
    ['post', '/api/users/auth/google/link'],
    ['post', '/api/users/phone/send-otp'],
    ['post', '/api/users/phone/verify-otp'],
  ];

  for (const [method, path] of GUARDED) {
    await t.test(`${method.toUpperCase()} ${path} still refuses without a token`, async () => {
      const res = await api[method](path)
        .set('X-Forwarded-For', uniqueClientIp()).set('Origin', ORIGIN).send({});
      assert.equal(res.status, 403, `${res.status}: ${JSON.stringify(res.body).slice(0, 140)}`);
    });
  }

  await t.test('the guarded list still matches server.js entry for entry', () => {
    // If a route is added to the app without being added here, this count
    // drifts and the new route goes untested.
    const server = readFileSync(new URL('../../server.js', import.meta.url), 'utf8');
    const registered = (server.match(/^app\.(post|put|delete|patch)\("[^"]+", csrfGuard\);$/gm) || []).length;
    assert.equal(registered, GUARDED.length, 'the csrfGuard list changed — update this suite');
  });
});
