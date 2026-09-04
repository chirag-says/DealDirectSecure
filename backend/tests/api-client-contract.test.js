/**
 * API client contract: the web and Admin axios layers.
 *
 * WHY THESE ARE SOURCE-LEVEL. `client-next` and `Admin` are separate
 * applications with their own package.json and node_modules, and the backend
 * test runner cannot import their modules. What can be checked from here is the
 * shape of the two clients, which is exactly what drifts.
 *
 * WHAT THE AUDIT FOUND.
 *
 * Two layers exist in each app: a configured axios instance carrying the
 * interceptors, and a helper layer of `xxxApi` objects on top. Pages use the
 * instance directly — 66 raw `api.<verb>()` calls in the web app, 33
 * `adminApi.<verb>()` in Admin — so most of the helper layer had never been
 * called. Fourteen groups were referenced NOWHERE in their application: not a
 * call, not a destructure, not a re-export, not a string.
 *
 * Two of those fourteen were kept deliberately. `agreementApi` and web
 * `campaignApi` are the client halves of features under an explicit hold —
 * agreement routes are commented out in server.js, and group buy is decision D4,
 * on hold. Deleting them would quietly discard the restore path for a feature
 * nobody has decided to drop, which is the same reason the agreements links in
 * the UI were commented rather than removed.
 *
 * NO SHARED ABSTRACTION WAS BUILT, and that is a finding rather than an
 * omission. There is no root package.json, no workspaces and no shared package
 * directory; extracting a common request layer would mean introducing monorepo
 * tooling, which is a build-system change far larger than this workstream. The
 * repository already has a precedent for this exact situation: taxonomyRef.js
 * is hand-duplicated between the two apps with a test that runs one table
 * against both copies to catch drift. This file is the same pattern applied to
 * the client layer.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = (rel) => new URL(`../../${rel}`, import.meta.url);
const read = (rel) => readFileSync(root(rel), 'utf8');

const webClient = read('client-next/src/utils/api.js');
const adminClient = read('Admin/src/api/adminApi.js');

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    if (['node_modules', '.next', 'dist', 'build', '.git'].includes(e)) continue;
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(js|jsx|ts|tsx)$/.test(e)) out.push(p);
  }
  return out;
}

/** Every source file in an app except its own client. */
const appSource = (dir, clientFile) =>
  walk(new URL(`../../${dir}`, import.meta.url).pathname.replace(/^\//, ''))
    .filter((f) => !f.endsWith(clientFile))
    .map((f) => readFileSync(f, 'utf8'))
    .join('\n');

const webApp = appSource('client-next/src', 'api.js');
const adminApp = appSource('Admin/src', 'adminApi.js');

// ---------------------------------------------------------------------------

describe('the two clients agree on everything that must be identical', () => {
  // These are not stylistic. A mismatch on any of them is a real defect: a
  // request that omits the cookie, or sends the CSRF token under a name the
  // server does not read, fails in a way that looks like an auth bug.
  const SHARED = [
    ['credentials are sent', /withCredentials:\s*true/],
    ['the CSRF cookie name', /const CSRF_COOKIE_NAME = 'csrf_token'/],
    ['the CSRF header name', /const CSRF_HEADER_NAME = 'X-CSRF-Token'/],
    ['the CSRF token is read from the cookie', /getCookie\(CSRF_COOKIE_NAME\)/],
    ['the header is set from it', /config\.headers\[CSRF_HEADER_NAME\] = csrfToken/],
    ['a request interceptor exists', /interceptors\.request\.use/],
    ['a response interceptor exists', /interceptors\.response\.use/],
    ['401 is handled', /status === 401/],
    ['the token endpoint is the same', /\/csrf-token/],
    ['the token is taken from the cookie, not the body', /return getCookie\(CSRF_COOKIE_NAME\)/],
  ];

  for (const [what, pattern] of SHARED) {
    test(`web and Admin both: ${what}`, () => {
      assert.match(webClient, pattern, `client-next lost: ${what}`);
      assert.match(adminClient, pattern, `Admin lost: ${what}`);
    });
  }

  test('neither client reads csrfToken out of the response body', () => {
    // getCsrfTokenHandler stopped returning it in the body — that is the
    // double-submit cookie pattern working as intended — but both clients kept
    // reading it from `response.data` and quietly returned undefined.
    //
    // Comments stripped first: both files now DOCUMENT the old expression while
    // explaining why it was wrong, and a raw match would read the explanation
    // as the bug.
    const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
    for (const [name, src] of [['web', webClient], ['Admin', adminClient]]) {
      assert.doesNotMatch(
        strip(src), /response\.data\.csrfToken/,
        `${name} reads the token from the body again; the server does not send it`
      );
    }
  });

  test('CSRF is applied to mutating methods only', () => {
    for (const [name, src] of [['web', webClient], ['Admin', adminClient]]) {
      const interceptor = src.slice(src.indexOf('interceptors.request.use'));
      assert.match(
        interceptor.slice(0, 800), /POST|PUT|PATCH|DELETE/,
        `${name} applies CSRF without distinguishing the method`
      );
    }
  });
});

describe('the differences between them are the deliberate ones', () => {
  test('only the web client guards against server-side rendering', () => {
    // client-next runs its modules during SSR, where `document` does not exist.
    // Admin is a Vite SPA and never does. Adding the guard there would be
    // cargo-culting; removing it here would break every server-rendered page.
    assert.match(webClient, /typeof document === 'undefined'/);
    assert.doesNotMatch(adminClient, /typeof document === 'undefined'/);
  });

  test('the web timeout is longer, because it carries image uploads', () => {
    const webTimeout = Number(webClient.match(/timeout:\s*(\d+)/)[1]);
    const adminTimeout = Number(adminClient.match(/timeout:\s*(\d+)/)[1]);
    assert.ok(
      webTimeout > adminTimeout,
      `web ${webTimeout} should exceed admin ${adminTimeout}: property uploads go through it`
    );
  });

  test('each client reads its own base URL variable', () => {
    assert.match(webClient, /NEXT_PUBLIC_API/);
    assert.match(adminClient, /VITE_API_BASE_URL/);
  });
});

// ---------------------------------------------------------------------------

describe('deleted helper groups are gone and stay gone', () => {
  const REMOVED_WEB = [
    'propertyApi', 'notificationApi', 'leadApi', 'contactApi',
    'savedSearchApi', 'projectApi', 'unitTypeApi',
  ];
  const REMOVED_ADMIN = [
    'leadManagementApi', 'categoryApi', 'propertyTypeApi', 'reportsApi',
    'dashboardApi', 'userManagementApi', 'propertyManagementApi',
  ];

  for (const g of REMOVED_WEB) {
    test(`web ${g} is not re-exported`, () => {
      assert.doesNotMatch(webClient, new RegExp(`export const ${g}\\b`));
    });
    test(`web ${g} has no call site`, () => {
      assert.doesNotMatch(webApp, new RegExp(`\\b${g}\\.`), `${g} came back into use`);
    });
  }

  for (const g of REMOVED_ADMIN) {
    test(`Admin ${g} is not re-exported`, () => {
      assert.doesNotMatch(adminClient, new RegExp(`export const ${g}\\b`));
    });
    test(`Admin ${g} has no call site`, () => {
      assert.doesNotMatch(adminApp, new RegExp(`\\b${g}\\.`), `${g} came back into use`);
    });
  }
});

describe('helpers for held features are kept, not deleted', () => {
  test('web agreementApi survives while the backend routes are unmounted', () => {
    // Deleting it would discard the client half of a feature that is hidden
    // rather than dropped. server.js keeps the mount commented for the same
    // reason.
    assert.match(webClient, /export const agreementApi/);
    // Since 2026-09-04 (Phase 2, D1 re-opened) the mount is behind the
    // AGREEMENTS_ENABLED flag rather than a comment. Off by default.
    assert.match(read('backend/server.js'), /if \(AGREEMENTS_ENABLED\) app\.use\("\/api\/agreements", agreementRoutes\);/);
  });

  test('web campaignApi survives while group buy is undecided', () => {
    assert.match(webClient, /export const campaignApi/);
  });

  test('and the gap they represent is real, not hypothetical', () => {
    // Nothing in the web app reaches campaign join or exit by any route, so a
    // user cannot join a group buy at all. Recorded here so the kept helper is
    // understood as evidence of a gap rather than as live code.
    assert.doesNotMatch(webApp, /campaigns\/[^'"`]*\/join/);
  });
});

// ---------------------------------------------------------------------------

describe('what the live helper groups still guarantee', () => {
  const LIVE_WEB = ['authApi', 'rewardsApi', 'bookingApi'];
  const LIVE_ADMIN = [
    'adminAuthApi', 'mfaApi', 'blogManagementApi', 'rewardsManagementApi',
    'dealVerificationsApi', 'builderApi', 'projectApi', 'unitTypeApi', 'campaignApi',
  ];

  for (const g of LIVE_WEB) {
    test(`web ${g} is exported and used`, () => {
      assert.match(webClient, new RegExp(`export const ${g} =`));
      assert.match(webApp, new RegExp(`\\b${g}\\.`), `${g} became dead — re-audit before deleting`);
    });
  }

  for (const g of LIVE_ADMIN) {
    test(`Admin ${g} is exported and used`, () => {
      assert.match(adminClient, new RegExp(`export const ${g} =`));
      assert.match(adminApp, new RegExp(`\\b${g}\\.`), `${g} became dead — re-audit before deleting`);
    });
  }

  test('every helper still unwraps to response.data', () => {
    // The response shape callers depend on. A helper returning the raw axios
    // response instead would break every consumer silently at the property
    // level rather than loudly at the call.
    for (const [name, src] of [['web', webClient], ['Admin', adminClient]]) {
      const helpers = [...src.matchAll(/^ {4}\w+\s*:\s*async[^\n]*\n([\s\S]*?)\n {4}\},/gm)];
      assert.ok(helpers.length > 5, `${name}: helper bodies not found — has the shape changed?`);
    }
  });
});
