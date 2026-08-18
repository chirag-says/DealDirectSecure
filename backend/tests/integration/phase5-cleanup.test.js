/**
 * Suite 24: Phase 5 cleanup batch 1.
 *
 * Four unrelated defects that happen to be small. Grouped because each is a few
 * lines and none needs a decision, not because they share a cause.
 *
 * 5.9  The /properties SEO block always rendered zero listings.
 * 5.10 The locality autocomplete facet has never returned anything.
 * 5.4  Six duplicate index declarations, two of which are not what they look
 *      like.
 * 5.11 A newsletter form that told users they had subscribed to nothing.
 * 5.2  Two orphaned components.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync, existsSync } from 'node:fs';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, seedTaxonomy } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const repo = (rel) => new URL(`../../../${rel}`, import.meta.url);
const readRepo = (rel) => readFileSync(repo(rel), 'utf8');
const get = (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp());

// Every "the bad code is gone" assertion below reads source and matches a
// pattern. Each fix also DOCUMENTS the defect it removed, in a comment that
// necessarily quotes it — so an unstripped match finds the explanation and
// reports the bug as still present. Strip comments first, and assert on code.
const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

// ---------------------------------------------------------------------------
// 5.10 — the locality facet
// ---------------------------------------------------------------------------

test('5.10 — suggestions return localities', async (t) => {
  /**
   * getSuggestions queried `address.locality`. That path does not exist: the
   * address subdocument holds line, area, city, state, pincode, landmark,
   * nearby, latitude and longitude. The locality lives at the TOP level of the
   * property, and production confirms it — 47 of 47 properties have
   * `locality`, and 0 have `address.locality`.
   *
   * So the facet returned nothing, for everyone, since it was written.
   */
  async function seedLocalities() {
    const owner = await makeOwner();
    const Property = M('Property');
    // Written the way real properties are: top-level city and locality, with
    // the address subdocument holding the fields it actually has.
    //
    // `address.area` deliberately does NOT repeat the locality. The free-text
    // $or matches area as well, so an area that echoes the locality makes the
    // search test pass whether or not the locality clause works — which is
    // exactly what it did on the first attempt, and the mutation caught it.
    return Property.insertMany([
      { title: 'A', owner: owner._id, isApproved: true, price: 1, listingType: 'Sell',
        city: 'Pune', locality: 'Baner', address: { city: 'Pune', area: 'Sector 1' } },
      { title: 'B', owner: owner._id, isApproved: true, price: 1, listingType: 'Sell',
        city: 'Pune', locality: 'Bavdhan', address: { city: 'Pune', area: 'Sector 2' } },
      { title: 'C', owner: owner._id, isApproved: true, price: 1, listingType: 'Sell',
        city: 'Mumbai', locality: 'Bandra', address: { city: 'Mumbai', area: 'Sector 3' } },
    ]);
  }

  await t.test('a locality prefix returns matching localities', async () => {
    await seedLocalities();
    const res = await get('/api/properties/suggestions?q=Ba');

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const localities = (res.body.suggestions || []).filter((s2) => s2.type === 'locality');
    assert.ok(localities.length > 0, `the facet returned nothing: ${JSON.stringify(res.body).slice(0, 250)}`);
  });

  await t.test('it returns the real locality values', async () => {
    await seedLocalities();
    const res = await get('/api/properties/suggestions?q=Ban');
    const names = (res.body.suggestions || [])
      .filter((s2) => s2.type === 'locality')
      .map((s2) => s2.value);

    assert.ok(names.some((n) => /Baner|Bandra/.test(n)), `got ${JSON.stringify(names)}`);
  });

  await t.test('a non-matching prefix returns none', async () => {
    await seedLocalities();
    const res = await get('/api/properties/suggestions?q=Zzzz');
    const localities = (res.body.suggestions || []).filter((s2) => s2.type === 'locality');
    assert.equal(localities.length, 0);
  });

  // getSuggestions was not the only caller. searchProperties builds a free-text
  // $or across title, description, address.city, address.area and locality —
  // and its locality clause was broken the same way, so searching for a
  // neighbourhood by name only ever hit properties whose TITLE happened to
  // contain it. Mutation testing found this: reverting the $or alone left every
  // suggestions test passing.
  await t.test('free-text search matches a locality name', async () => {
    await seedLocalities();
    const res = await get('/api/properties/search?search=Bavdhan');

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const found = res.body.data || res.body.properties || res.body;
    const titles = (Array.isArray(found) ? found : []).map((p2) => p2.title);
    assert.deepEqual(titles, ['B'], `searching a locality returned ${JSON.stringify(titles)}`);
  });

  await t.test('free-text search still matches the other fields', async () => {
    // Guards the fix against having replaced the clause instead of correcting it.
    await seedLocalities();
    const res = await get('/api/properties/search?search=Mumbai');
    const found = res.body.data || res.body.properties || res.body;
    assert.equal((Array.isArray(found) ? found : []).length, 1, 'the city clause stopped working');
  });

  await t.test('the controller no longer queries the non-existent path', () => {
    const src = stripComments(
      readFileSync(new URL('../../controllers/propertyController.js', import.meta.url), 'utf8')
    );
    const fn = src.slice(src.indexOf('export const getSuggestions'));
    const body = fn.slice(0, fn.indexOf('\nexport const '));
    assert.doesNotMatch(
      body, /address\.locality/,
      'address has no locality path — line, area, city, state, pincode, landmark, nearby, lat, long'
    );
  });

  await t.test('and the schema still has no address.locality, so this stays true', () => {
    const model = readFileSync(new URL('../../models/Property.js', import.meta.url), 'utf8');
    const addressBlock = model.slice(model.indexOf('address: {'), model.indexOf('},', model.indexOf('address: {')));
    assert.doesNotMatch(addressBlock, /locality/, 'address gained a locality path — re-decide which one is canonical');
  });
});

// ---------------------------------------------------------------------------
// 5.4 — duplicate index declarations
// ---------------------------------------------------------------------------

test('5.4 — each index is declared exactly once', async (t) => {
  /**
   * Six warnings on every boot. Each was a field carrying `index: true` or
   * `unique: true` inline AND a matching single-field `schema.index()` call.
   *
   * Removing a duplicate DECLARATION does not touch a deployed index — Mongoose
   * creates indexes, it never drops them — so this is a code change, not a
   * database one. What it must not do is remove the only declaration of an
   * index that differs from the inline one, which is exactly the trap in the
   * two session models: their explicit `expiresAt` index is a TTL, and the
   * inline `index: true` is the redundant half.
   */
  const model = (f) => readFileSync(new URL(`../../models/${f}`, import.meta.url), 'utf8');

  const DUPLICATES = [
    ['Admin.js', /adminSchema\.index\(\{\s*email:\s*1\s*\}\)/, 'email'],
    ['userModel.js', /userSchema\.index\(\{\s*email:\s*1\s*\}/, 'email'],
    ['userModel.js', /userSchema\.index\(\{\s*referralCode:\s*1\s*\}/, 'referralCode'],
    ['Role.js', /roleSchema\.index\(\{\s*name:\s*1\s*\}\)/, 'name'],
  ];

  for (const [file, pattern, field] of DUPLICATES) {
    await t.test(`${file}: the redundant ${field} index declaration is gone`, () => {
      assert.doesNotMatch(model(file), pattern);
    });
  }

  await t.test('but the inline uniqueness that replaced it survives', () => {
    // The constraint must still exist — only the second declaration went.
    assert.match(model('Admin.js').slice(0, 3000), /unique:\s*true/);
    assert.match(model('userModel.js').slice(0, 3000), /unique:\s*true/);
    assert.match(model('Role.js').slice(0, 2000), /unique:\s*true/);
  });

  for (const file of ['AdminSession.js', 'UserSession.js']) {
    await t.test(`${file}: the TTL index survives and the inline flag went`, () => {
      const src = model(file);
      // The TTL is the one that matters — it is what removes expired sessions.
      assert.match(src, /expireAfterSeconds:\s*0/, `${file} lost its TTL index`);

      const block = src.slice(src.indexOf('expiresAt: {'), src.indexOf('}', src.indexOf('expiresAt: {')));
      assert.doesNotMatch(block, /index:\s*true/, `${file} still declares expiresAt twice`);
    });
  }

  await t.test('loading every model emits no duplicate-index warning', () => {
    // The observable form of the fix. Asserted on the source rather than by
    // capturing process warnings, because the models are already loaded by the
    // time any test runs.
    const files = ['Admin.js', 'userModel.js', 'Role.js', 'AdminSession.js', 'UserSession.js'];
    for (const f of files) {
      const src = model(f);
      const explicit = [...src.matchAll(/\.index\(\s*\{\s*(\w+):\s*-?1\s*\}/g)].map((m) => m[1]);
      for (const field of explicit) {
        const inline = new RegExp(`${field}:\\s*\\{[^{}]*?(?:index:\\s*true|unique:\\s*true)`, 's');
        assert.doesNotMatch(
          src, inline,
          `${f}: ${field} is declared both inline and explicitly`
        );
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 5.9 / 5.11 / 5.2 — client-side cleanup, asserted at source
// ---------------------------------------------------------------------------

test('5.9 — the properties page reads a bare array', async (t) => {
  const page = () => readRepo('client-next/src/app/properties/page.js');

  /**
   * This page is a Next.js server component in a different application with its
   * own build, so the backend suite cannot import it. Matching the source for
   * `Array.isArray(` is not good enough either — mutation testing showed why:
   * the categories line uses `Array.isArray` too, so the assertion passed with
   * the properties fix reverted.
   *
   * So extract the shipped expression and evaluate it. That tests the real
   * behaviour of the real code, and it fails if the assignment is reverted.
   */
  const normaliseAs = (propsData) => {
    const src = page();
    const start = src.indexOf('const properties =');
    assert.notEqual(start, -1, 'the properties assignment was renamed or removed');
    const expr = src.slice(src.indexOf('=', start) + 1, src.indexOf(';', start));
    return new Function('propsData', `return (${expr});`)(propsData);
  };

  await t.test('a bare array — the shape the endpoint actually returns', () => {
    // /api/properties/list returns a BARE ARRAY, confirmed in Phase 4.3 and
    // recorded in mobile's type definitions. An array has neither `.data` nor
    // `.properties`, so `propsData?.data || propsData?.properties || []` always
    // produced [] and the hidden SEO block rendered zero listings, every request.
    assert.deepEqual(normaliseAs([{ _id: 'a' }, { _id: 'b' }]), [{ _id: 'a' }, { _id: 'b' }]);
  });

  await t.test('an envelope still works, if the endpoint ever grows one', () => {
    assert.deepEqual(normaliseAs({ data: [{ _id: 'a' }] }), [{ _id: 'a' }]);
    assert.deepEqual(normaliseAs({ properties: [{ _id: 'a' }] }), [{ _id: 'a' }]);
  });

  await t.test('a failed fetch degrades to empty rather than throwing', () => {
    // ssrFetch returns null on failure. The page must render, not 500.
    assert.deepEqual(normaliseAs(null), []);
    assert.deepEqual(normaliseAs(undefined), []);
  });

  await t.test('an empty array stays empty and is not confused with failure', () => {
    assert.deepEqual(normaliseAs([]), []);
  });
});

test('5.11 — the newsletter no longer claims a subscription that did not happen', async (t) => {
  // Comments stripped for the same reason as above: the Footer now RECORDS what
  // it removed and why, so a raw match would read the explanation as the defect.
  const footer = () => stripComments(readRepo('client-next/src/components/Footer/Footer.jsx'));

  await t.test('the fabricated success message is gone', () => {
    // There is no newsletter backend: no route, no model, no controller, no
    // other UI. The form validated the address, waited 500 ms, and told the
    // user they had subscribed to nothing.
    assert.doesNotMatch(footer(), /Subscribed successfully/);
  });

  await t.test('the simulated call is gone with it', () => {
    assert.doesNotMatch(footer(), /Simulate API call/);
    assert.doesNotMatch(footer(), /handleSubscribe/);
  });

  await t.test('no newsletter endpoint was invented to replace it', () => {
    // The alternative fix would have been to build a subscription service. That
    // is a product decision, not a cleanup.
    const routes = readFileSync(new URL('../../routes', import.meta.url).pathname.replace(/^\//, '') + '/userRoutes.js', 'utf8');
    assert.doesNotMatch(routes, /newsletter|subscribe/i);
  });
});

test('5.2 — the two orphaned components are gone', async (t) => {
  for (const rel of [
    'client-next/src/components/HeroSection/HeroSection_omnibox.jsx',
    'client-next/src/components/MiddelComp.jsx',
  ]) {
    await t.test(`${rel.split('/').pop()} is deleted`, () => {
      assert.equal(existsSync(repo(rel)), false, `${rel} is back`);
    });
  }

  await t.test('the components that were NOT orphaned survive', () => {
    // Guards against over-deletion. Both of these were candidates in the audit
    // and turned out to be live.
    for (const rel of [
      'client-next/src/components/SampleAgreement/AgreementGenerator.jsx',
      'client-next/src/components/LogoLoop/LogoLoop.jsx',
      'client-next/src/components/Footer/Footer.jsx',
      'client-next/src/components/Navbar/Navbar.jsx',
    ]) {
      assert.ok(existsSync(repo(rel)), `${rel} was deleted but is in use`);
    }
  });
});
