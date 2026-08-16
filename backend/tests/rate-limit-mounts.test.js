/**
 * Rate-limit mounts — the limiter must be attached to the route that exists.
 *
 * Two of the six tiers were dead: groupBuyLimiter pointed at a prefix no router
 * is mounted under, and authLimiter's coverage stopped short of four auth
 * routes because app.use matches on a segment boundary.
 *
 * These tests cross-check every mount in server.js against the route actually
 * registered in the router file, and assert the mount runs before its router.
 * Limits are not asserted by value — this fix changes coverage, not thresholds.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §19.3, F-S8.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const server = read('../server.js');
const userRoutes = read('../routes/userRoutes.js');
const adminRoutes = read('../routes/adminRoutes.js');
const campaignRoutes = read('../routes/campaignRoutes.js');
const propertyRoutes = read('../routes/propertyRoutes.js');

const mountedAt = (path, limiter) => {
  const re = new RegExp(
    `app\\.use\\(\\s*['"]${path.replace(/[/:]/g, (c) => '\\' + c)}['"]\\s*,\\s*${limiter}\\s*\\)`
  );
  const m = server.match(re);
  return m ? server.indexOf(m[0]) : -1;
};

const routerMountAt = (prefix) =>
  server.indexOf(`app.use("${prefix}",`);

describe('auth limiter covers every credential and OTP endpoint', () => {
  // [mount path, route file, registered route path]
  const cases = [
    ['/api/users/login', userRoutes, '/login'],
    ['/api/users/register', userRoutes, '/register'],
    ['/api/users/register-direct', userRoutes, '/register-direct'],
    ['/api/users/verify-otp', userRoutes, '/verify-otp'],
    ['/api/users/resend-otp', userRoutes, '/resend-otp'],
    ['/api/users/forgot-password', userRoutes, '/forgot-password'],
    ['/api/users/reset-password', userRoutes, '/reset-password'],
    ['/api/admin/login', adminRoutes, '/login'],
    ['/api/admin/mfa/verify', adminRoutes, '/mfa/verify'],
  ];

  for (const [mount, routeSrc, routePath] of cases) {
    test(`${mount} has authLimiter attached`, () => {
      assert.notEqual(mountedAt(mount, 'authLimiter'), -1, `${mount} is not rate limited`);
    });

    test(`${mount} corresponds to a real registered route`, () => {
      const re = new RegExp(`router\\.post\\(\\s*["']${routePath}["']`);
      assert.match(routeSrc, re, `${routePath} is not registered — the mount would be dead`);
    });
  }

  test('register-direct is mounted separately from register', () => {
    // app.use matches on a segment boundary, so "/api/users/register" does not
    // cover "/api/users/register-direct". This is the whole reason the route
    // was unprotected; asserting it explicitly so the mount is not "tidied away".
    assert.notEqual(mountedAt('/api/users/register-direct', 'authLimiter'), -1);
    assert.notEqual(mountedAt('/api/users/register', 'authLimiter'), -1);
  });

  test('every auth limiter runs before its router', () => {
    const usersAt = routerMountAt('/api/users');
    const adminAt = routerMountAt('/api/admin');
    assert.ok(usersAt > 0 && adminAt > 0);
    for (const [mount] of cases) {
      const at = mountedAt(mount, 'authLimiter');
      const routerAt = mount.startsWith('/api/users') ? usersAt : adminAt;
      assert.ok(at < routerAt, `${mount} limiter is registered after its router and will never run`);
    }
  });
});

describe('group-buy limiter is attached to the real campaign routes', () => {
  test('join is limited', () => {
    assert.notEqual(mountedAt('/api/campaigns/:id/join', 'groupBuyLimiter'), -1);
  });

  test('exit is limited', () => {
    assert.notEqual(mountedAt('/api/campaigns/:id/exit', 'groupBuyLimiter'), -1);
  });

  test('the join and exit routes actually exist under that prefix', () => {
    assert.match(campaignRoutes, /router\.post\(\s*["']\/:id\/join["']/);
    assert.match(campaignRoutes, /router\.post\(\s*["']\/:id\/exit["']/);
    assert.ok(routerMountAt('/api/campaigns') > 0, '/api/campaigns router is not mounted');
  });

  test('the dead /api/group-buy mount is gone', () => {
    assert.doesNotMatch(
      server,
      /\/api\/group-buy/,
      'a limiter on a prefix with no router is dead code that reads as protection'
    );
  });

  test('the limiter runs before the campaigns router', () => {
    const at = mountedAt('/api/campaigns/:id/join', 'groupBuyLimiter');
    assert.ok(at > 0 && at < routerMountAt('/api/campaigns'));
  });

  test('it runs before the CSRF guard on the same route', () => {
    // Not required for correctness, but it means an abusive caller is turned
    // away before any token work happens.
    const limiterAt = mountedAt('/api/campaigns/:id/join', 'groupBuyLimiter');
    const csrfAt = server.indexOf('app.post("/api/campaigns/:id/join", csrfGuard)');
    assert.ok(csrfAt > 0, 'campaign join lost its CSRF guard');
    assert.ok(limiterAt < csrfAt);
  });
});

describe('search limiter mounts still match real routes', () => {
  for (const [mount, routePath] of [
    ['/api/properties/search', '/search'],
    ['/api/properties/suggestions', '/suggestions'],
    ['/api/properties/filter', '/filter'],
  ]) {
    test(`${mount} is limited and registered`, () => {
      assert.notEqual(mountedAt(mount, 'searchLimiter'), -1);
      const re = new RegExp(`router\\.get\\(\\s*["']${routePath}["']`);
      assert.match(propertyRoutes, re);
    });
  }
});

describe('limits themselves are unchanged', () => {
  test('authLimiter is still 5 per 15 minutes with skipSuccessfulRequests', () => {
    const block = server.slice(server.indexOf('const authLimiter'), server.indexOf('const authLimiter') + 500);
    assert.match(block, /max:\s*5/);
    assert.match(block, /skipSuccessfulRequests:\s*true/);
  });

  test('groupBuyLimiter is still 10 per 15 minutes', () => {
    const block = server.slice(server.indexOf('const groupBuyLimiter'), server.indexOf('const groupBuyLimiter') + 400);
    assert.match(block, /max:\s*10/);
    assert.match(block, /windowMs:\s*15 \* 60 \* 1000/);
  });

  test('searchLimiter is still 20 per minute', () => {
    const block = server.slice(server.indexOf('const searchLimiter'), server.indexOf('const searchLimiter') + 400);
    assert.match(block, /max:\s*20/);
  });

  test('globalLimiter is still 500 per 15 minutes', () => {
    const block = server.slice(server.indexOf('const globalLimiter'), server.indexOf('const globalLimiter') + 400);
    assert.match(block, /max:\s*500/);
  });
});

describe('agreement limiters remain declared for re-enablement', () => {
  test('they are still mounted even though the router is commented out', () => {
    // Deliberate: they become live again the moment the agreements mount is
    // restored. Documented in server.js.
    assert.notEqual(mountedAt('/api/agreements/generate', 'transactionalLimiter'), -1);
    assert.notEqual(mountedAt('/api/agreements/webhook', 'webhookLimiter'), -1);
    // Raw source: the mount is itself a comment, so the stripped copy cannot see it.
    const serverRaw = readFileSync(new URL('../server.js', import.meta.url), 'utf8');
    assert.match(serverRaw, /\/\/ app\.use\("\/api\/agreements", agreementRoutes\);/);
  });
});
