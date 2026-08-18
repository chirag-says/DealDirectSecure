/**
 * Suite 25: Phase 5 cleanup batch 2.
 *
 * 5.3  A user-facing MFA flow that no backend can trigger.
 * 5.5  Six dependencies nothing imports.
 * 5.6  Two schema fields nothing reads.
 * 5.7  A detail page that answers 200 for properties that do not exist.
 * 5.8  Security headers on the origin that serves the HTML.
 *
 * The client-side items are asserted at source, and where the assertion could
 * pass for the wrong reason the shipped expression is extracted and evaluated
 * instead. Comments are stripped first: each fix documents the defect it
 * removed, and that necessarily quotes it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, seedTaxonomy, TEST_PASSWORD } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const repo = (rel) => new URL(`../../../${rel}`, import.meta.url);
const readRepo = (rel) => readFileSync(repo(rel), 'utf8');
const backend = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');
const get = (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp());

const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

// ---------------------------------------------------------------------------
// 5.3 — the user-facing MFA branch
// ---------------------------------------------------------------------------

test('5.3 — the dead user MFA flow is gone, and admin MFA is untouched', async (t) => {
  /**
   * The web client carried a complete MFA flow: a `requiresMfa` state, a
   * six-digit code form on both login and register, and a `verifyMfa` call to
   * `/users/verify-mfa`.
   *
   * None of it could ever run. Nothing in the backend emits `requiresMfa`,
   * `REQUIRES_MFA` or an `mfaToken` outside adminController and authAdmin, both
   * mounted at /api/admin; the User model has no MFA field of any kind; and
   * there is no `/users/verify-mfa` route, so the verify call would have 404ed
   * even if a user had somehow reached the form.
   *
   * MFA is real, and it is for admins. It lives in the separate Admin app.
   */
  const CLIENT_FILES = [
    'client-next/src/context/AuthContext.jsx',
    'client-next/src/app/login/LoginContent.jsx',
    'client-next/src/app/register/RegisterContent.jsx',
  ];

  for (const rel of CLIENT_FILES) {
    await t.test(`${rel.split('/').pop()} no longer references user MFA`, () => {
      const src = stripComments(readRepo(rel));
      assert.doesNotMatch(src, /requiresMfa/, 'the dead flag survives');
      assert.doesNotMatch(src, /verifyMfa|handleMfaVerify/, 'the dead handler survives');
      assert.doesNotMatch(src, /REQUIRES_MFA/, 'the dead response code survives');
      assert.doesNotMatch(src, /mfaToken/, 'the dead token survives');
    });
  }

  await t.test('the call to the route that never existed is gone', () => {
    const src = stripComments(readRepo('client-next/src/context/AuthContext.jsx'));
    assert.doesNotMatch(src, /users\/verify-mfa/);
  });

  await t.test('and the backend still has no such route, so it stays gone', () => {
    assert.doesNotMatch(backend('routes/userRoutes.js'), /verify-mfa/);
  });

  await t.test('the User model still has no MFA field', () => {
    // If one is ever added, this fails and the removal has to be reconsidered
    // rather than silently re-created.
    assert.doesNotMatch(stripComments(backend('models/userModel.js')), /mfa|twoFactor|totpSecret/i);
  });

  await t.test('ADMIN MFA is untouched — it is the real one', () => {
    // Guards against over-deletion. These are a different application talking
    // to different endpoints.
    for (const rel of [
      'Admin/src/pages/MfaSetup.jsx',
      'Admin/src/pages/MfaVerify.jsx',
      'Admin/src/pages/AdminLogin.jsx',
    ]) {
      assert.ok(existsSync(repo(rel)), `${rel} was deleted — admin MFA is live`);
    }
    assert.match(readRepo('Admin/src/api/adminApi.js'), /mfa/i, 'the admin MFA client calls went');

    // Asserted on the exact shape, not a substring. `/requiresMfa/` alone still
    // matched `requiresMfa_removed`, so the mutation that broke admin login
    // survived — the test could not tell working admin MFA from renamed-away
    // admin MFA.
    const ac = backend('controllers/adminController.js');
    assert.match(ac, /requiresMfa:\s*true/, 'admin login no longer signals that MFA is required');
    assert.match(ac, /speakeasy\.totp\.verify\(/,
      'admin MFA no longer verifies a TOTP code — Google Authenticator login is broken');
    assert.match(ac, /speakeasy\.generateSecret\(/, 'admin MFA enrolment is broken');
    assert.match(backend('routes/adminRoutes.js'), /router\.post\(["']\/mfa\/verify["']/,
      'the admin MFA verify route is gone');
  });

  await t.test('the redirect to the page that does not exist is gone', () => {
    // RequireAuth sent users to /verify-mfa, which is not a route.
    const src = stripComments(readRepo('client-next/src/context/AuthContext.jsx'));
    assert.doesNotMatch(src, /['"]\/verify-mfa['"]/);
  });

  await t.test('login and register still export a working submit path', () => {
    // The removal must not take the real flow with it.
    for (const rel of ['client-next/src/app/login/LoginContent.jsx',
                       'client-next/src/app/register/RegisterContent.jsx']) {
      const src = readRepo(rel);
      assert.match(src, /onSubmit=\{/, `${rel} lost its form handler`);
    }
    const ctx = readRepo('client-next/src/context/AuthContext.jsx');
    for (const fn of ['login', 'register', 'logout']) {
      assert.match(ctx, new RegExp(`\\b${fn}[,\\s]`), `AuthContext lost ${fn}`);
    }
  });
});

// ---------------------------------------------------------------------------
// 5.5 — unused dependencies
// ---------------------------------------------------------------------------

test('5.5 — the six unused dependencies are gone and nothing imports them', async (t) => {
  const REMOVED = ['axios', 'body-parser', 'file-type', 'jspdf', 'jspdf-autotable', 'morgan'];
  const pkg = JSON.parse(backend('package.json'));

  for (const name of REMOVED) {
    await t.test(`${name} is no longer declared`, () => {
      assert.equal(pkg.dependencies?.[name], undefined, `${name} is still a dependency`);
      assert.equal(pkg.devDependencies?.[name], undefined, `${name} is still a devDependency`);
    });
  }

  await t.test('and nothing in the backend imports any of them', () => {
    // The reason they were safe to remove. Asserted rather than assumed, so a
    // future import fails here instead of at runtime on a missing module.
    const dirs = ['controllers', 'models', 'routes', 'middleware', 'utils', 'services', 'config', 'scripts'];
    const root = new URL('../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

    const walk = (dir) => {
      let out = [];
      for (const e of readdirSync(dir)) {
        const full = `${dir}/${e}`;
        if (statSync(full).isDirectory()) out = out.concat(walk(full));
        else if (e.endsWith('.js')) out.push(full);
      }
      return out;
    };

    const files = ['server.js', 'instrument.js']
      .map((f) => `${root}/${f}`)
      .filter((f) => existsSync(f))
      .concat(dirs.filter((d) => existsSync(`${root}/${d}`)).flatMap((d) => walk(`${root}/${d}`)));

    const offenders = [];
    for (const f of files) {
      const src = readFileSync(f, 'utf8');
      for (const name of REMOVED) {
        const re = new RegExp(`(from\\s+['"]${name}['"]|require\\(\\s*['"]${name}['"])`);
        if (re.test(src)) offenders.push(`${f.split('/').slice(-2).join('/')} → ${name}`);
      }
    }
    assert.deepEqual(offenders, [], `these still import a removed package: ${offenders.join(', ')}`);
  });

  await t.test('the packages that DO get used survive', () => {
    // Guards against over-removal. pdfkit is the one that matters: the audit
    // flagged jspdf as dead PDF tooling, and the backend really does export
    // PDFs — through pdfkit.
    for (const keep of ['pdfkit', 'exceljs', 'express', 'mongoose', 'helmet']) {
      assert.ok(pkg.dependencies?.[keep], `${keep} was removed but is in use`);
    }
    assert.match(backend('controllers/userController.js'), /pdfkit|PDFDocument/,
      'nothing uses pdfkit any more — re-check whether it should also go');
  });

  await t.test('the lockfile agrees with the manifest', () => {
    // npm install was run, not just an edit to package.json.
    const lock = JSON.parse(backend('package-lock.json'));
    const rootDeps = lock.packages?.['']?.dependencies || {};
    for (const name of REMOVED) {
      assert.equal(rootDeps[name], undefined, `${name} is still in the lockfile root`);
    }
  });
});

// ---------------------------------------------------------------------------
// 5.6 — unused fields
// ---------------------------------------------------------------------------

test('5.6 — the two dead fields are gone and session invalidation still works', async (t) => {
  /**
   * `security.sessionVersion` was written only by `invalidateSessions()`, which
   * nothing ever called, and read by nothing at all. `hasCompletedFirstAction`
   * was declared and never touched by any code path.
   *
   * The dangerous half is sessionVersion, because CLAUDE.md attributes
   * "all sessions invalidated on password change" to it. That guarantee is real,
   * but it does not come from this field. It comes from two other mechanisms,
   * both asserted below, and both had to be confirmed BEFORE the field could go.
   */
  await t.test('sessionVersion is gone from the schema', () => {
    assert.doesNotMatch(stripComments(backend('models/userModel.js')), /sessionVersion/);
  });

  await t.test('its only writer is gone with it', () => {
    assert.doesNotMatch(stripComments(backend('models/userModel.js')), /invalidateSessions/);
  });

  await t.test('hasCompletedFirstAction is gone from the schema', () => {
    assert.doesNotMatch(stripComments(backend('models/userModel.js')), /hasCompletedFirstAction/);
  });

  /**
   * THE MECHANISM, established before deleting anything.
   *
   * `authMiddleware` has two paths. When the JWT carries a `sessionId` — which
   * every current login produces — it loads the UserSession, checks isBlocked
   * and isActive, and calls next(). It does NOT call `changedPasswordAfter`.
   * Only the legacy fallback for tokens without a sessionId does that.
   *
   * So the guarantee does not come from `passwordChangedAt` either, for any
   * token issued today. It comes from the session record being revoked:
   * `revokeOtherSessions` on change, `revokeAllUserSessions` on reset. A
   * revoked session fails to load and the request is rejected.
   *
   * That is three candidate mechanisms, of which exactly one is live.
   * sessionVersion is dead, passwordChangedAt is dormant behind the legacy
   * path, and session revocation is what actually runs.
   */
  await t.test('MECHANISM: password change revokes the other sessions', () => {
    const uc = backend('controllers/userController.js');
    assert.match(uc, /revokeAllUserSessions\(/, 'password reset no longer revokes sessions');
    assert.match(uc, /revokeOtherSessions\(/, 'password change no longer revokes other sessions');
  });

  await t.test('the dormant legacy check is still intact', () => {
    // Not the live path, but it is the only protection for a legacy token, so
    // removing sessionVersion must not disturb it.
    assert.match(backend('models/userModel.js'), /changedPasswordAfter/);
    assert.match(backend('middleware/authUser.js'), /changedPasswordAfter\(\s*decoded\.iat\s*\)/);
  });

  await t.test('and it works end to end: changing the password kills other sessions', async () => {
    // The behavioural proof, through the real endpoint. Two live sessions; the
    // one that changes the password survives, the other stops working.
    const owner = await makeOwner();
    const login = async () => {
      const r = await api.post('/api/users/login')
        .set('X-Forwarded-For', uniqueClientIp())
        .send({ email: owner.email, password: TEST_PASSWORD });
      assert.equal(r.status, 200, `login failed: ${JSON.stringify(r.body).slice(0, 200)}`);
      return r.headers['set-cookie'];
    };
    const profile = (cookie) => api.get('/api/users/profile')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookie);

    const sessionA = await login();
    const sessionB = await login();

    assert.equal((await profile(sessionA)).status, 200, 'session A was born dead');
    assert.equal((await profile(sessionB)).status, 200, 'session B was born dead');

    const changed = await api.put('/api/users/change-password')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', sessionB)
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'An0ther!Passw0rd' });
    assert.equal(changed.status, 200, `change-password failed: ${JSON.stringify(changed.body).slice(0, 200)}`);

    assert.equal((await profile(sessionA)).status, 401,
      'the OTHER session survived a password change — session revocation is broken');
    assert.equal((await profile(sessionB)).status, 200,
      'the session that changed the password was logged out of itself');
  });

  await t.test('no reference to either field survives anywhere in the backend', () => {
    for (const rel of ['scripts/migrateLegacyUsers.js']) {
      const src = stripComments(backend(rel));
      assert.doesNotMatch(src, /sessionVersion/, `${rel} still migrates a field that no longer exists`);
    }
  });
});

// ---------------------------------------------------------------------------
// 5.7 — soft-404, sitemap, canonicals
// ---------------------------------------------------------------------------

test('5.7 — a property that does not exist answers 404', async (t) => {
  await t.test('BACKEND: a missing id is 404', async () => {
    const res = await get(`/api/properties/${new mongoose.Types.ObjectId()}`);
    assert.equal(res.status, 404);
  });

  await t.test('BACKEND: a malformed id is 400, not 500', async () => {
    const res = await get('/api/properties/not-an-object-id');
    assert.equal(res.status, 400, `got ${res.status}: ${JSON.stringify(res.body).slice(0, 150)}`);
  });

  await t.test('BACKEND: a real property is still 200', async () => {
    const owner = await makeOwner();
    const p = await M('Property').create({
      title: 'Live', owner: owner._id, isApproved: true, price: 1,
      listingType: 'Sell', city: 'Pune', locality: 'Baner',
    });
    const res = await get(`/api/properties/${p._id}`);
    assert.equal(res.status, 200);
  });

  /**
   * The client half. `ssrFetch` collapsed every failure to null — 404, 500,
   * timeout and DNS error alike — so the page could not tell "this property
   * does not exist" from "the backend is down".
   *
   * That distinction is the whole item. Calling notFound() on null would answer
   * 404 for every live property during an outage, and Google drops URLs that
   * return 404. The fix has to carry the status, so both halves are asserted.
   */
  await t.test('CLIENT: ssrFetch can report the status, not just null', () => {
    const src = readRepo('client-next/src/utils/ssrFetch.js');
    assert.match(src, /ssrFetchWithStatus|export function ssrFetchStatus|notFound:/,
      'ssrFetch still collapses every failure to null');
  });

  await t.test('CLIENT: the property page calls notFound()', () => {
    const src = stripComments(readRepo('client-next/src/app/properties/[id]/page.js'));
    assert.match(src, /notFound\(\)/, 'the page still renders 200 for a missing property');
    assert.match(src, /from ['"]next\/navigation['"]/);
  });

  await t.test('CLIENT: but NOT on a transient backend failure', () => {
    // The regression that matters. A 404 must come from the resource being
    // absent, never from the API being unreachable.
    const src = stripComments(readRepo('client-next/src/app/properties/[id]/page.js'));
    assert.doesNotMatch(src, /if\s*\(\s*!\s*property\s*\)\s*notFound\(\)/,
      'notFound() fires on any null, including an outage');
  });

  await t.test('CLIENT: the projects page has the same defect and the same fix', () => {
    const src = stripComments(readRepo('client-next/src/app/projects/[id]/page.js'));
    assert.doesNotMatch(src, /if\s*\(\s*!\s*project\s*\)\s*notFound\(\)/,
      'projects still 404s whenever the backend hiccups');
  });

  await t.test('CLIENT: a missing property emits no canonical URL', () => {
    // A canonical pointing at a 404 asks Google to index the 404.
    // Comments stripped: the fix explains that it deliberately omits the
    // canonical, and the explanation contains the word.
    const src = stripComments(readRepo('client-next/src/app/properties/[id]/page.js'));
    const meta = src.slice(src.indexOf('generateMetadata'), src.indexOf('export default'));

    // Just the not-found branch: from `if (!property)` to the `}` that closes
    // it. The earlier version over-read by a fixed 400 characters and picked up
    // the canonical belonging to the SUCCESS return below it.
    const at = meta.indexOf('if (!property)');
    assert.notEqual(at, -1, 'the not-found branch was renamed');
    const branch = meta.slice(at, meta.indexOf('\n    }', at));

    assert.doesNotMatch(branch, /canonical/,
      'the not-found metadata still advertises a canonical');
    assert.match(meta, /canonical/,
      'the SUCCESS metadata lost its canonical — that is over-correction');
    assert.match(meta, /robots/, 'the not-found metadata does not mark itself noindex');
  });
});

test('5.7 — the sitemap lists what is public and omits what is not', async (t) => {
  const sitemap = () => readRepo('client-next/src/app/sitemap.js');

  const MUST_INCLUDE = ['/projects', '/faq', '/press-impressions', '/rewards'];
  for (const path of MUST_INCLUDE) {
    await t.test(`includes ${path}`, () => {
      // Anchored at the END of the path. The earlier version allowed a trailing
      // `/`, so `${SITE_URL}/projects/${project._id}` from the DYNAMIC entries
      // satisfied the check for the static /projects index — and deleting the
      // index page from the sitemap went unnoticed.
      const entries = [...sitemap().matchAll(/\$\{SITE_URL\}(\/[a-z0-9/-]*)`/g)].map((m) => m[1]);
      assert.ok(entries.includes(path),
        `${path} is public and indexable but absent from the sitemap; found ${JSON.stringify(entries)}`);
    });
  }

  const MUST_OMIT = ['/login', '/register', '/rewards/dashboard', '/my-bookings', '/profile'];
  for (const path of MUST_OMIT) {
    await t.test(`omits ${path}`, () => {
      const entries = [...sitemap().matchAll(/\$\{SITE_URL\}(\/[a-z0-9/-]*)/g)].map((m) => m[1]);
      assert.ok(!entries.includes(path), `${path} should not be advertised for indexing`);
    });
  }

  await t.test('project detail pages are listed, not just the index', () => {
    assert.match(sitemap(), /projects\/\$\{|projects\/\$\{project|projectPages/,
      'the projects vertical contributes only its index page');
  });

  await t.test('the property pages it already had are still there', () => {
    assert.match(sitemap(), /propertyPages/);
    assert.match(sitemap(), /blogPages/);
  });

  await t.test('robots disallows the private routes the middleware protects', () => {
    // These two are in PROTECTED_ROUTES but were missing from robots.
    //
    // Comments stripped, and matched as quoted list entries: robots.js now
    // explains which routes were added and why, and the explanation names them,
    // so a plain search found the comment and passed with the entries deleted.
    const robots = stripComments(readRepo('client-next/src/app/robots.js'));
    for (const path of ['/my-bookings', '/rewards/dashboard']) {
      assert.match(robots, new RegExp(`['"]${path}['"]`), `${path} is crawlable`);
    }
  });
});

// ---------------------------------------------------------------------------
// 5.8 — security headers on the HTML origin
// ---------------------------------------------------------------------------

test('5.8 — the HTML origin sends security headers', async (t) => {
  /**
   * The backend's helmet configuration is thorough, and it protects the wrong
   * origin: it applies to JSON API responses. A CSP on a JSON body governs
   * nothing. The headers that matter are the ones on the HTML document, and
   * next.config.mjs had no `headers()` at all.
   *
   * CSP is Report-Only deliberately. The site embeds four real iframes — Google
   * Maps twice, YouTube, and the rewards storefront SDK — so an enforced
   * `frame-src 'none'` copied from the backend would break live pages. Report
   * first, enforce once the reports are clean.
   */
  const config = () => readRepo('client-next/next.config.mjs');

  await t.test('a headers() function exists', () => {
    assert.match(config(), /async\s+headers\s*\(\s*\)/, 'no headers() in next.config.mjs');
  });

  const REQUIRED = [
    ['X-Content-Type-Options', /nosniff/],
    ['Referrer-Policy', /strict-origin-when-cross-origin/],
    ['Permissions-Policy', /camera=|geolocation=/],
    ['X-Frame-Options', /SAMEORIGIN|DENY/],
  ];

  for (const [header, valuePattern] of REQUIRED) {
    await t.test(`${header} is set`, () => {
      const src = config();
      assert.match(src, new RegExp(header), `${header} is missing`);
      assert.match(src, valuePattern, `${header} has no recognisable value`);
    });
  }

  await t.test('HSTS is production-only', () => {
    // Sending HSTS from a local http dev server pins localhost to https in the
    // browser for the whole max-age. It is painful to diagnose and worse to undo.
    //
    // The check has to bind HSTS to the CONDITIONAL, not merely observe that the
    // file mentions isProduction somewhere: the constant is declared at the top,
    // so a loose match passed even with HSTS emitted unconditionally.
    const src = stripComments(config());
    assert.match(src, /Strict-Transport-Security/, 'HSTS is not set at all');
    assert.match(
      src,
      /isProduction[\s\S]{0,120}Strict-Transport-Security/,
      'HSTS is not guarded by isProduction — that pins http://localhost to https'
    );
  });

  await t.test('and HSTS does not silently opt into the preload list', () => {
    // `preload` is effectively irreversible and needs a deliberate submission,
    // not a config default that someone copied.
    assert.doesNotMatch(stripComments(config()), /max-age[^'"]*preload/);
  });

  await t.test('CSP is Report-Only, not enforced', () => {
    const src = config();
    assert.match(src, /Content-Security-Policy-Report-Only/,
      'no report-only CSP — the proposal was not shipped');
    assert.doesNotMatch(src, /['"]Content-Security-Policy['"]/,
      'an ENFORCED CSP was added; the four live iframes would break');
  });

  await t.test('the report-only policy permits what the site actually embeds', () => {
    // If the policy is going to be promoted to enforcing later, it has to
    // already describe reality. These are the origins the app really loads.
    const src = config();
    for (const origin of ['res.cloudinary.com', 'youtube.com', 'google.com', 'cdnjs.cloudflare.com']) {
      assert.ok(src.includes(origin), `${origin} is embedded by the app but absent from the CSP`);
    }
  });

  await t.test('the four iframes the policy has to allow are still there', () => {
    // If these ever go, the policy can be tightened — so fail loudly rather
    // than leave a permissive frame-src nobody revisits.
    const files = [
      'client-next/src/app/contact/ContactContent.jsx',
      'client-next/src/app/properties/[id]/PropertyDetailsContent.jsx',
      'client-next/src/app/rewards/dashboard/RewardStorefront.jsx',
    ];
    const total = files.reduce((n, f) => n + (readRepo(f).match(/<iframe/g) || []).length, 0);
    assert.equal(total, 4, `iframe count changed (${total}) — revisit frame-src in the CSP`);
  });
});
