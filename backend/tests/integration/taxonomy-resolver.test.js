/**
 * Suite 7: Taxonomy reference resolution.
 *
 * Guards the fix for the defect that corrupted the property corpus. The old
 * resolver tried exact, then case-insensitive, then substring. The substring
 * step resolved the category "Residential" to the document named
 * "Residential Plot", and "Commercial" to "Commercial Land"; when nothing
 * matched at all, the caller stamped `metadata.propertyTypes[0]._id`, which is
 * how apartments, villas and penthouses were all recorded as type "Plot".
 * Twenty-five of forty-seven listings carry refs that describe a different
 * property than the one they belong to, and not one of them is correct.
 *
 * Two things are asserted here, and they are different claims:
 *
 *   1. The resolver itself refuses everything except an exact match. Tested as a
 *      pure function against BOTH copies, because the repository has no shared
 *      package and the web and Admin apps carry hand-duplicated twins. Running
 *      one table against both is what catches the copies drifting apart, which
 *      is the obvious way this fix decays.
 *
 *   2. Creating a property through the real API still works, and a listing whose
 *      taxonomy cannot be resolved is stored with no reference rather than a
 *      wrong one.
 *
 * The second matters because the resolver runs in the browser. The backend does
 * not currently validate that a submitted `category` ref agrees with the
 * submitted `categoryName`, so these tests prove the clients stopped guessing,
 * not that the server would refuse a guess. That gap is recorded, not closed:
 * closing it is a change to the create contract and belongs with the migration.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, loginAs } from './setup/factories.js';

import * as webResolver from '../../../client-next/src/utils/taxonomyRef.js';
import * as adminResolver from '../../../Admin/src/utils/taxonomyRef.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');

/** The two hand-duplicated copies, exercised by the same table. */
const COPIES = [
  ['client-next', webResolver],
  ['Admin', adminResolver],
];

/** A taxonomy shaped like the one that caused the damage. */
const TAXONOMY = [
  { _id: '69209a69a447a8e227a860d8', name: 'Residential Plot' },
  { _id: '69209a69a447a8e227a860de', name: 'Commercial Land' },
  { _id: '69209a66a447a8e227a8604f', name: 'Apartment' },
  { _id: '691d66a3b579aceb778157e4', name: 'Office Space' },
  { _id: '691b06b02f50359a4f05f604', name: 'Office space' },
];

// ---------------------------------------------------------------------------

for (const [app, resolver] of COPIES) {
  test(`resolver contract (${app})`, async (t) => {
    const { resolveTaxonomyRef } = resolver;

    await t.test('an exact category name resolves to its id', () => {
      const r = resolveTaxonomyRef('Residential Plot', TAXONOMY);
      assert.equal(r.matched, true);
      assert.equal(r.id, '69209a69a447a8e227a860d8');
    });

    await t.test('an exact property type name resolves to its id', () => {
      const r = resolveTaxonomyRef('Apartment', TAXONOMY);
      assert.equal(r.matched, true);
      assert.equal(r.id, '69209a66a447a8e227a8604f');
    });

    await t.test('a substring of a real name is refused', () => {
      // The exact input that started the corruption: "Residential" is a
      // substring of "Residential Plot".
      const r = resolveTaxonomyRef('Residential', TAXONOMY);
      assert.equal(r.matched, false, '"Residential" must not resolve to "Residential Plot"');
      assert.equal(r.id, null);
    });

    await t.test('the other half of the original corruption is refused too', () => {
      const r = resolveTaxonomyRef('Commercial', TAXONOMY);
      assert.equal(r.matched, false, '"Commercial" must not resolve to "Commercial Land"');
      assert.equal(r.id, null);
    });

    await t.test('a name that merely contains a real name is refused', () => {
      // The reverse direction: the old matcher tested both ways round in
      // different call sites.
      const r = resolveTaxonomyRef('Luxury Apartment Tower', TAXONOMY);
      assert.equal(r.matched, false);
      assert.equal(r.id, null);
    });

    await t.test('a case variant is refused', () => {
      // Deliberate. The taxonomy holds both "Office Space" and "Office space"
      // as separate documents, so folding case would make the result depend on
      // array order.
      const r = resolveTaxonomyRef('OFFICE SPACE', TAXONOMY);
      assert.equal(r.matched, false);
      assert.equal(r.id, null);
    });

    await t.test('each spelling of the duplicate resolves to its own document', () => {
      assert.equal(resolveTaxonomyRef('Office Space', TAXONOMY).id, '691d66a3b579aceb778157e4');
      assert.equal(resolveTaxonomyRef('Office space', TAXONOMY).id, '691b06b02f50359a4f05f604');
    });

    await t.test('an unknown name is refused', () => {
      const r = resolveTaxonomyRef('Apartment / Flat', TAXONOMY);
      assert.equal(r.matched, false, 'the canonical name does not exist in the taxonomy yet');
      assert.equal(r.id, null);
      assert.match(r.reason, /no document named/);
    });

    await t.test('no fallback to the first element, or to any unrelated id', () => {
      // The specific shape of the second bug: a miss used to return
      // documents[0]._id. With a single-element taxonomy the difference between
      // "refused" and "fell back" is unmistakable.
      const single = [{ _id: '69209a69a447a8e227a860d5', name: 'Plot' }];
      const r = resolveTaxonomyRef('Apartment / Flat', single);
      assert.equal(r.matched, false);
      assert.equal(r.id, null, 'a miss must never return the only document present');

      // And across the full table, no miss may return any id at all.
      for (const miss of ['Residential', 'Commercial', 'Villa', '', 'Office']) {
        assert.equal(resolveTaxonomyRef(miss, TAXONOMY).id, null, `"${miss}" leaked an id`);
      }
    });

    await t.test('an unloaded or empty taxonomy is refused, not guessed', () => {
      for (const docs of [[], null, undefined]) {
        const r = resolveTaxonomyRef('Residential Plot', docs);
        assert.equal(r.matched, false);
        assert.equal(r.id, null);
      }
    });

    await t.test('the wrapper returns the id, or null with a reason logged', () => {
      const { taxonomyRefOrNull } = resolver;
      assert.equal(taxonomyRefOrNull('Apartment', TAXONOMY, 'test'), '69209a66a447a8e227a8604f');

      const warnings = [];
      const original = console.warn;
      console.warn = (...args) => warnings.push(args.join(' '));
      try {
        assert.equal(taxonomyRefOrNull('Residential', TAXONOMY, 'categories'), null);
      } finally {
        console.warn = original;
      }
      assert.equal(warnings.length, 1, 'a miss should be visible, not silent');
      assert.match(warnings[0], /not sending a reference/);
    });
  });
}

// ---------------------------------------------------------------------------

test('the two copies have not drifted apart', async (t) => {
  await t.test('both agree on every case in the table', () => {
    const inputs = [
      'Residential Plot', 'Commercial Land', 'Apartment', 'Office Space',
      'Office space', 'Residential', 'Commercial', 'OFFICE SPACE',
      'Apartment / Flat', 'Luxury Apartment Tower', '', 'Plot',
    ];
    for (const input of inputs) {
      const web = webResolver.resolveTaxonomyRef(input, TAXONOMY);
      const admin = adminResolver.resolveTaxonomyRef(input, TAXONOMY);
      assert.deepEqual(
        { id: web.id, matched: web.matched },
        { id: admin.id, matched: admin.matched },
        `the web and Admin copies disagree on "${input}"`
      );
    }
  });
});

// ---------------------------------------------------------------------------

test('property creation still works', async (t) => {
  async function createWith(body) {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const res = await api
      .post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ title: 'Resolver Suite', listingType: 'Sell', latitude: 11.11, longitude: 77.77, ...body });
    return { res, owner, doc: await Property().findOne({ owner: owner._id }).lean() };
  }

  await t.test('a listing with names but no refs is created and keeps its names', async () => {
    // The state every listing is in until the taxonomy migration runs: the
    // canonical names do not exist in the taxonomy, so the resolver returns null
    // and the client sends no reference.
    const { res, doc } = await createWith({
      categoryName: 'Residential',
      propertyTypeName: 'Apartment / Flat',
    });

    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
    assert.equal(doc.categoryName, 'Residential');
    assert.equal(doc.propertyTypeName, 'Apartment / Flat');
    assert.ok(!doc.category, 'no reference should be invented');
    assert.ok(!doc.propertyType, 'no reference should be invented');
  });

  await t.test('a resolved reference is stored as sent', async () => {
    const type = await mongoose.model('PropertyType').create({ name: 'Residential' });
    const category = await mongoose.model('Category').create({
      name: 'Apartment', propertyType: type._id,
    });

    const { res, doc } = await createWith({
      categoryName: 'Residential',
      propertyTypeName: 'Apartment',
      category: String(category._id),
      propertyType: String(type._id),
    });

    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
    assert.equal(String(doc.category), String(category._id));
    assert.equal(String(doc.propertyType), String(type._id));
  });

  await t.test('an empty-string reference does not become a stored value', async () => {
    // The Admin form used to append "" on a resolver miss. Whatever the server
    // does with that, it must not end up as a reference on the document.
    const { res, doc } = await createWith({
      categoryName: 'Residential',
      propertyTypeName: 'Villa',
      category: '',
      propertyType: '',
    });

    if (res.status === 201) {
      assert.ok(!doc.category, 'an empty string must not survive as a reference');
      assert.ok(!doc.propertyType, 'an empty string must not survive as a reference');
    } else {
      // Rejecting outright is also acceptable; silently storing something is not.
      assert.ok(res.status >= 400);
      assert.equal(doc, null);
    }
  });
});
