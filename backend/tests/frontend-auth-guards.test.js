/**
 * Frontend authentication guards (Phase 2.4)
 *
 * INVARIANT: every private client-next route is covered by BOTH layers —
 * the edge middleware redirect and an in-content useAuth guard — so an
 * unauthenticated visitor is redirected to /login rather than rendering the
 * screen and hitting a raw 401.
 *
 * These read the actual client source. There is no frontend test runner in this
 * repo and adding one would be architecture work, so the guard *configuration*
 * is asserted here and the guard *behaviour* was verified by inspection of the
 * middleware matching rules (documented per-test).
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §20.1 (F-FE1 ProtectedRoute dead,
 * F-FE2 /my-bookings unguarded).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const CLIENT = new URL('../../client-next/src/', import.meta.url);
const readClient = (rel) => readFileSync(new URL(rel, CLIENT), 'utf8');
const clientExists = (rel) => existsSync(new URL(rel, CLIENT));

const middleware = readClient('middleware.js');

/** Every private route, with the *Content.jsx that renders it. */
const PRIVATE_ROUTES = [
  ['/profile', 'app/profile/ProfileContent.jsx'],
  ['/my-properties', 'app/my-properties/MyPropertiesContent.jsx'],
  ['/add-property', 'app/add-property/AddPropertyContent.jsx'],
  ['/edit-property', 'app/edit-property/[id]/EditPropertyContent.jsx'],
  ['/notifications', 'app/notifications/NotificationsContent.jsx'],
  ['/saved-properties', 'app/saved-properties/SavedPropertiesContent.jsx'],
  ['/my-bookings', 'app/my-bookings/MyBookingsContent.jsx'],
  ['/rewards/dashboard', 'app/rewards/dashboard/RewardsDashboardContent.jsx'],
];

/** Reproduces the middleware's own prefix rule. */
const middlewareProtects = (pathname) => {
  const list = middleware
    .slice(middleware.indexOf('const PROTECTED_ROUTES'), middleware.indexOf('];', middleware.indexOf('const PROTECTED_ROUTES')))
    .match(/'([^']+)'/g)
    .map((s) => s.replace(/'/g, ''));
  return list.some((route) => pathname === route || pathname.startsWith(route + '/'));
};

describe('every private route is covered by the edge middleware', () => {
  for (const [route] of PRIVATE_ROUTES) {
    test(`${route} redirects a guest at the edge`, () => {
      assert.ok(
        middlewareProtects(route),
        `${route} is absent from PROTECTED_ROUTES — a guest renders the page and hits a 401`
      );
    });
  }

  test('a nested path under a private route is also covered', () => {
    assert.ok(middlewareProtects('/edit-property/507f1f77bcf86cd799439011'));
    assert.ok(middlewareProtects('/my-properties/anything'));
  });

  test('the guest redirect carries the origin and a reason', () => {
    assert.match(middleware, /new URL\('\/login', request\.url\)/);
    assert.match(middleware, /searchParams\.set\('from', pathname\)/);
    assert.match(middleware, /searchParams\.set\('message'/);
  });

  test('the redirect only fires when there is definitely no session', () => {
    // Cross-origin deployments may not expose session_exists at the edge;
    // redirecting on absence alone would lock out authenticated users.
    assert.match(middleware, /definitelyNoSession/);
    assert.match(middleware, /!sessionExists/);
  });
});

describe('public routes are not caught by the middleware', () => {
  const PUBLIC = ['/', '/properties', '/properties/abc123', '/projects', '/blog', '/about', '/contact', '/login', '/register', '/faq', '/terms'];

  for (const route of PUBLIC) {
    test(`${route} stays public`, () => {
      assert.equal(middlewareProtects(route), false, `${route} would redirect guests away`);
    });
  }

  test('the /rewards marketing page stays reachable when logged out', () => {
    // '/rewards/dashboard' is listed, not '/rewards'. Protecting the parent
    // would hide the only page that explains the rewards programme.
    assert.equal(middlewareProtects('/rewards'), false);
    assert.equal(middlewareProtects('/rewards/terms'), false);
    assert.equal(middlewareProtects('/rewards/dashboard'), true);
  });
});

describe('every private route also guards in-content', () => {
  for (const [route, file] of PRIVATE_ROUTES) {
    test(`${route} checks useAuth and redirects`, () => {
      assert.ok(clientExists(file), `${file} not found — was the route moved?`);
      const src = readClient(file);
      assert.match(src, /useAuth\(\)/, `${file} does not read auth state`);
      assert.match(
        src,
        /router\.(push|replace)\(\s*[`'"]\/login/,
        `${file} never redirects an unauthenticated visitor`
      );
    });
  }

  test('the guard waits for the auth check before deciding', () => {
    // Redirecting while `loading` is true would bounce authenticated users on
    // every hard refresh, before checkAuth resolves.
    for (const [, file] of PRIVATE_ROUTES) {
      const src = readClient(file);
      assert.match(src, /authLoading|loading:\s*authLoading|!loading/, `${file} may redirect before auth resolves`);
    }
  });
});

describe('/my-bookings no longer reaches a raw 401', () => {
  const src = readClient('app/my-bookings/MyBookingsContent.jsx');

  test('it is covered by the middleware', () => {
    assert.ok(middlewareProtects('/my-bookings'));
  });

  test('it has an in-content guard', () => {
    assert.match(src, /useAuth\(\)/);
    assert.match(src, /router\.push\('\/login\?from=\/my-bookings'\)/);
  });

  test('it does not fetch bookings before auth is confirmed', () => {
    // The bug: the effect called getMyBookings() unconditionally, so a guest
    // triggered a 401 whose message rendered as "Failed to load bookings".
    const effect = src.slice(src.indexOf('useEffect(() => {', src.indexOf('MyBookingsContent')));
    const guardAt = effect.indexOf('isAuthenticated');
    const fetchAt = effect.indexOf('fetch_()');
    assert.ok(guardAt !== -1 && fetchAt !== -1);
    assert.ok(guardAt < fetchAt, 'the fetch must be gated on the auth check');
  });

  test('the unconditional fetch-on-mount is gone', () => {
    assert.doesNotMatch(src, /useEffect\(\(\) => \{ fetch_\(\); \}, \[\]\)/);
  });
});

describe('ProtectedRoute stays unused, deliberately', () => {
  const authContext = readClient('context/AuthContext.jsx');

  test('it is still not wired into any route', () => {
    // Adopting it would add a third mechanism alongside the middleware and the
    // in-content guards, which already cover every private route.
    const appFiles = PRIVATE_ROUTES.map(([, f]) => readClient(f));
    for (const src of appFiles) {
      assert.doesNotMatch(src, /<ProtectedRoute/, 'a screen started using ProtectedRoute');
    }
  });

  test('the reason is recorded where the next reader will look', () => {
    assert.match(authContext, /NOT IN USE/);
  });

  test('its redirect targets still do not exist, which is why', () => {
    for (const route of ['app/verify-mfa', 'app/change-password-required', 'app/verify-email']) {
      assert.equal(clientExists(route), false, `${route} now exists — revisit the ProtectedRoute decision`);
    }
    assert.match(authContext, /router\.replace\('\/verify-mfa'\)/);
  });
});

describe('SSR architecture is untouched', () => {
  test('ssrFetch still returns null instead of throwing', () => {
    const ssrFetch = readClient('utils/ssrFetch.js');
    assert.match(ssrFetch, /return null/);
    assert.match(ssrFetch, /AbortController/);
  });

  test('no page.js became a client component', () => {
    for (const route of ['app/my-bookings/page.js', 'app/profile/page.js', 'app/rewards/dashboard/page.js']) {
      if (!clientExists(route)) continue;
      assert.doesNotMatch(readClient(route), /^'use client'/m, `${route} would lose SSR and metadata`);
    }
  });

  test('the middleware matcher still excludes api and static assets', () => {
    assert.match(middleware, /\(\?!api\|_next\/static\|_next\/image\|favicon\.ico/);
  });
});
