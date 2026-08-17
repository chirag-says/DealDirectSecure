/**
 * Suite 3: Property field contract, end to end.
 *
 * The highest-value suite in this set, because the failure it guards against is
 * silent. `sanitizePropertyData` copies only whitelisted names, so a field
 * missing from the list is dropped with no error: the owner fills it in, the UI
 * reports success, and the value is gone. That is what produced the taxonomy and
 * priceUnit bugs, and nothing in the unit tests could see it: the whitelist and
 * the schema each looked fine in isolation. Only a round trip through the real
 * endpoint shows whether a submitted value actually lands.
 *
 * So every assertion here is a round trip: POST the field, read the stored
 * document, check the value arrived. Values are collision-proof sentinels
 * (`zzq<field>zzq`, or 9-million-range numbers) so a match cannot be a
 * coincidence. An earlier version of this suite searched for small integers and
 * booleans and reported fields as persisted when the value it found belonged to
 * something else entirely.
 *
 * Booleans and enum-constrained fields are excluded from the generated sweep for
 * that reason: `true` and the first enum value are not distinguishable from a
 * schema default. They are covered individually where they matter.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, makeProperty, loginAs, seedTaxonomy } from './setup/factories.js';
import {
  PROPERTY_ALLOWED_FIELDS, ADMIN_ONLY_FIELDS,
} from '../../controllers/propertyController.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');

/**
 * Fields that must survive a create. Held as an explicit list rather than
 * derived, so that a field silently falling out of the pipeline breaks this
 * test instead of quietly shrinking the expectation.
 */
// propertyTypeName and categoryName are excluded from the sentinel sweep on
// purpose: they are no longer free text. The server-side contract resolves them
// against real taxonomy documents and rejects anything it cannot match exactly,
// so a sentinel would be a 400 rather than a stored value. They are asserted
// with canonical values in their own tests below.
const MUST_PERSIST = [
  'description', 'city', 'locality',
  'price', 'deposit', 'maintenance', 'securityDeposit',
  'bhk', 'bedrooms', 'bathrooms', 'balconies', 'totalFloors',
  'furnishing', 'facing', 'amenities', 'powerBackup', 'constructionStatus',
  'meetingRooms', 'pantry', 'washrooms',
  // Added by the Phase 0/1 field-contract reconciliation. priceUnit in
  // particular: the form sends "Monthly"/"Total", and dropping it left the
  // schema default "Lac", which the price filter multiplies by 1e5.
  'priceUnit', 'gstApplicable', 'bookingAmount', 'videoUrl', 'ageOfProperty',
  'floorNo', 'propertyAge', 'allowedFor', 'petFriendly',
  // A Date, and the reason sameValue() exists. It always persisted; the first
  // version of this suite compared it as a string and mislabelled it discarded.
  'availableFrom',
  // Commercial configuration block
  'commercialSubType', 'loadingArea', 'shutters', 'floorHeight', 'powerLoad',
  'workstations', 'conferenceRooms', 'cabins', 'frontage', 'storage',
  'displayWindows', 'displayArea', 'seatingCapacity', 'kitchenArea', 'barArea',
  'outdoorSeating', 'privateCabins', 'phoneBooths', 'loungeArea', 'loadingDocks',
  'ceilingHeight', 'floorLoadCapacity', 'powerConnection', 'overheadCrane', 'centralAC',
];

/**
 * Transient inputs: names the edit form submits that are not schema paths, and
 * that `updateMyProperty` translates before writing.
 *
 * The edit form serialises its whole state object flat
 * (EditPropertyContent.jsx:636, `Object.entries(formData).forEach(...append)`),
 * so it sends `carpetArea` where the schema wants `area.carpetSqft`. The
 * translation at propertyController.js:1395-1568 is what makes that work, and
 * it is invisible from either side on its own: the whitelist shows a name with
 * no schema path, and the schema shows a path no client ever names.
 *
 * Each entry is asserted to land at exactly the path given. A mapping that
 * quietly stops running would otherwise look identical to a field the user
 * left blank.
 */
const TRANSIENT_INPUTS = [
  { field: 'landmark', path: 'address.landmark' },
  { field: 'expectedPrice', path: 'price' },
  { field: 'expectedDeposit', path: 'deposit' },
  { field: 'bhkType', path: 'bhk' },
  { field: 'builtUpArea', path: 'area.builtUpSqft' },
  { field: 'carpetArea', path: 'area.carpetSqft' },
  { field: 'superBuiltUpArea', path: 'area.superBuiltUpSqft' },
  { field: 'plotArea', path: 'area.plotSqft' },
  { field: 'parkingCovered', path: 'parking.covered' },
  { field: 'parkingOpen', path: 'parking.open' },
  { field: 'reraId', path: 'legal.reraId' },
  { field: 'propertyCategory', path: 'categoryName' },
];

/**
 * Names removed from the whitelist in Phase 3A.1.
 *
 * No form sent them, they matched no schema path, and no property code read
 * them, so they advertised support that did not exist. They must not come back
 * without a mapping to go with them.
 */
const REMOVED_FROM_WHITELIST = [
  'floor', 'age', 'availability', 'possessionDate', 'waterSupply',
  'ownershipType', 'buildingName', 'buildingType', 'seatCapacity',
];

/**
 * A value that cannot be confused with a default or another field's data.
 *
 * `pathName` is where the value is expected to END UP, which is not always the
 * name it is submitted under. It matters: `expectedPrice` has no schema path of
 * its own, so typing it by its own name yields a string, and updateMyProperty
 * does `Number(data.expectedPrice)` on the way to `price` and casts NaN. Typing
 * by the destination gives a number, which is what the mapping expects.
 */
function sentinelFor(field, index, pathName = field) {
  const path = Property().schema.path(pathName)
    || Property().schema.path(field)
    || Property().schema.path(`location.${field}`);
  // Mixed accepts anything; a number is the more useful probe because the
  // mappings that target Mixed paths (parking counts) are numeric in practice.
  const instance = path?.instance === 'Mixed' ? 'Number' : (path?.instance || 'String');
  switch (instance) {
    case 'Number': return 9000000 + index;
    case 'Date': return `20${30 + (index % 9)}-0${1 + (index % 9)}-1${index % 9}T00:00:00.000Z`;
    case 'Array': return [`zzq${field}zzq`];
    default: return `zzq${field}zzq`;
  }
}

/**
 * Normalise a stored value for comparison against what was submitted.
 *
 * Dates need their own case. A Date read back from Mongo stringifies as
 * "Wed Jan 01 2031 ..." while the submitted value was an ISO string, so a
 * plain String() comparison never matches and the field looks discarded. That
 * is not hypothetical: it is why `availableFrom` sat in the discarded list
 * through Phase 3A when it had been persisting correctly the whole time.
 */
function sameValue(stored, submitted) {
  if (stored instanceof Date) {
    const asDate = new Date(submitted);
    return !Number.isNaN(asDate.getTime()) && stored.getTime() === asDate.getTime();
  }
  return String(stored) === String(submitted);
}

/** Find where a value came to rest in the stored document, or null. */
function locate(doc, needle, prefix = '') {
  for (const [key, value] of Object.entries(doc || {})) {
    const here = prefix ? `${prefix}.${key}` : key;
    if (value instanceof Date) {
      if (sameValue(value, needle)) return here;
    } else if (value && typeof value === 'object') {
      const found = locate(value, needle, here);
      if (found) return found;
    } else if (sameValue(value, needle)) {
      return here;
    }
  }
  return null;
}

/** Create a property through the real endpoint and return the stored document. */
async function createProperty(extra = {}) {
  const owner = await makeOwner();
  const cookies = await loginAs(api, owner);

  const res = await api
    .post('/api/properties/add')
    .set('X-Forwarded-For', uniqueClientIp())
    .set('Cookie', cookies)
    // latitude/longitude must be numeric: addProperty parseFloat()s them into
    // address.latitude, and a non-numeric value fails the cast and 500s.
    .send({ title: 'Contract Test Property', listingType: 'Sell', latitude: 11.11, longitude: 77.77, ...extra });

  return { res, owner, cookies, doc: await Property().findOne({ owner: owner._id }).lean() };
}

// ---------------------------------------------------------------------------

test('create round-trip', async (t) => {
  await t.test('every field that must persist actually reaches the database', async () => {
    const payload = {};
    const sentinels = {};
    MUST_PERSIST.forEach((field, i) => {
      const value = sentinelFor(field, i + 1);
      payload[field] = value;
      sentinels[field] = Array.isArray(value) ? value[0] : value;
    });

    const { res, doc } = await createProperty(payload);
    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 300));
    assert.ok(doc, 'the property should have been stored');

    const missing = Object.entries(sentinels)
      .filter(([, needle]) => !locate(doc, needle))
      .map(([field]) => field);

    assert.deepEqual(
      missing, [],
      `these whitelisted fields were accepted but never stored: ${missing.join(', ')}`
    );
  });

  await t.test('priceUnit survives, so the price filter reads the right scale', async () => {
    const { doc } = await createProperty({ price: 45000, priceUnit: 'Monthly', listingType: 'Rent' });
    assert.equal(doc.priceUnit, 'Monthly', 'a dropped priceUnit falls back to the "Lac" default');
    assert.equal(doc.price, 45000);
  });

  await t.test('canonical taxonomy names resolve to their documents', async () => {
    const { doc } = await createProperty({ categoryName: 'Commercial', propertyTypeName: 'Office Space' });
    assert.equal(doc.categoryName, 'Commercial');
    assert.equal(doc.propertyTypeName, 'Office Space');
    assert.ok(doc.category, 'the category reference should be resolved server-side');
    assert.ok(doc.propertyType, 'the property type reference should be resolved server-side');
  });

  await t.test('an unrecognised category is rejected, not bucketed', async () => {
    // This used to be bucketed by substring and defaulted to "Residential" when
    // nothing matched, which is how a listing could end up filed under a
    // category its owner never chose. Guessing is now a 400.
    const { res } = await createProperty({ categoryName: 'Nonsense Category' });
    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
  });

  await t.test('the new listing belongs to the caller and is auto-published', async () => {
    const { doc, owner } = await createProperty();
    assert.equal(String(doc.owner), String(owner._id));
    // Auto-publish is deliberate, propertyController.js:406 sets isApproved
    // server-side via setAdminOnlyFields, described there as a client
    // requirement. Pinning it so a change to that policy is a visible decision
    // rather than a silent one.
    assert.equal(doc.isApproved, true);
    assert.equal(doc.status, 'active');
  });
});

// ---------------------------------------------------------------------------

test('mass assignment is refused', async (t) => {
  await t.test('admin-only fields in the request body are ignored', async () => {
    const impostor = await makeOwner();

    const { doc, owner } = await createProperty({
      owner: impostor._id,        // reassign ownership
      // Sent as false, against the server-side default of true. If the body
      // reached the document this would flip; that it does not is the proof.
      isApproved: false,
      status: 'sold',             // fake a sale
      views: 999999,              // inflate popularity
      likes: 999999,
      inquiries: 999999,
      builder: new mongoose.Types.ObjectId(), // move to the builder feed
      isBanned: true,
      _id: new mongoose.Types.ObjectId(),
    });

    assert.equal(String(doc.owner), String(owner._id), 'owner must come from the session, not the body');
    assert.notEqual(String(doc.owner), String(impostor._id));
    assert.equal(doc.isApproved, true, 'isApproved must come from the server, not the request');
    assert.notEqual(doc.status, 'sold', 'status must not be settable from a request');
    assert.notEqual(doc.isBanned, true);
    assert.notEqual(doc.views, 999999);
    assert.notEqual(doc.likes, 999999);
    assert.notEqual(doc.inquiries, 999999);
    // Stored as null rather than left unset, so check for absence of a value
    // rather than a specific one.
    assert.ok(!doc.builder, 'builder decides the feed and must never come from a body');
  });

  await t.test('every admin-only name is absent from the accepted-field list', () => {
    // A name appearing in both lists would make the whitelist the weaker of the
    // two, since sanitize copies before the admin filter is considered.
    const overlap = ADMIN_ONLY_FIELDS.filter((f) => PROPERTY_ALLOWED_FIELDS.includes(f));
    assert.deepEqual(overlap, [], `these fields are both allowed and admin-only: ${overlap.join(', ')}`);
  });

  await t.test('a field nobody declared is discarded', async () => {
    const { doc } = await createProperty({
      somethingNobodyDeclared: 'zzqundeclaredzzq',
      'constructor.prototype.polluted': 'zzqpollutedzzq',
    });
    assert.equal(locate(doc, 'zzqundeclaredzzq'), null);
    assert.equal(locate(doc, 'zzqpollutedzzq'), null);
    assert.equal({}.polluted, undefined, 'prototype must be untouched');
  });
});

// ---------------------------------------------------------------------------

test('update round-trip', async (t) => {
  await t.test('an owner update persists whitelisted fields', async () => {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner);

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({
        title: 'Updated Title',
        description: 'zzqupdateddescriptionzzq',
        price: 9100001,
        priceUnit: 'Total',
        videoUrl: 'zzqupdatedvideozzq',
      });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 300));

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Updated Title');
    assert.equal(stored.description, 'zzqupdateddescriptionzzq');
    assert.equal(stored.price, 9100001);
    assert.equal(stored.priceUnit, 'Total');
    assert.equal(stored.videoUrl, 'zzqupdatedvideozzq');
  });

  await t.test('an owner update cannot approve the listing or reassign it', async () => {
    const owner = await makeOwner();
    const other = await makeOwner();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner, { isApproved: false, views: 7 });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ title: 'Still Mine', isApproved: true, owner: other._id, views: 888888 });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 300));

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Still Mine', 'the legitimate part of the update should apply');
    assert.notEqual(stored.isApproved, true, 'an owner must not approve their own disapproved listing');
    assert.equal(String(stored.owner), String(owner._id));
    assert.notEqual(stored.views, 888888);
  });
});

// ---------------------------------------------------------------------------

test('transient inputs are translated on update', async (t) => {
  /** Apply every transient input at once and return the stored document. */
  async function updateWithTransients() {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner);

    const payload = {};
    const sentinels = {};
    TRANSIENT_INPUTS.forEach(({ field, path }, i) => {
      // propertyCategory is not free-form: it selects a bucket, so it has to be
      // a real one for the assertion to mean anything.
      const value = field === 'propertyCategory' ? 'Commercial' : sentinelFor(field, i + 700, path);
      payload[field] = value;
      sentinels[field] = Array.isArray(value) ? value[0] : value;
    });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send(payload);

    return { res, sentinels, doc: await Property().findById(property._id).lean() };
  }

  await t.test('each one lands on the schema path it maps to', async () => {
    const { res, sentinels, doc } = await updateWithTransients();
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 300));

    const wrong = [];
    for (const { field, path } of TRANSIENT_INPUTS) {
      const found = locate(doc, sentinels[field]);
      if (found !== path) wrong.push(`${field}: expected ${path}, got ${found || 'nowhere'}`);
    }

    assert.deepEqual(wrong, [], `mapping broken for:\n  ${wrong.join('\n  ')}`);
  });

  await t.test('the transient name itself is not stored alongside the mapped one', async () => {
    // If both were written the document would carry two sources of truth for
    // the same number, and a later read could pick either.
    const { doc } = await updateWithTransients();
    for (const { field } of TRANSIENT_INPUTS) {
      assert.equal(
        doc[field], undefined,
        `"${field}" is an input name, not a stored field; it must not appear at the top level`
      );
    }
  });
});

// ---------------------------------------------------------------------------

test('names removed from the whitelist stay removed', async (t) => {
  await t.test('none of them is in the accepted-field list', () => {
    const resurrected = REMOVED_FROM_WHITELIST.filter((f) => PROPERTY_ALLOWED_FIELDS.includes(f));
    assert.deepEqual(
      resurrected, [],
      `these were removed for having no mapping and no schema path; ` +
      `re-adding one without wiring it up recreates the silent-discard bug: ${resurrected.join(', ')}`
    );
  });

  await t.test('submitting them changes nothing, on create or on update', async () => {
    const payload = {};
    const sentinels = {};
    REMOVED_FROM_WHITELIST.forEach((field, i) => {
      const value = sentinelFor(field, i + 800);
      payload[field] = value;
      sentinels[field] = Array.isArray(value) ? value[0] : value;
    });

    const { res: createRes, doc: created } = await createProperty(payload);
    assert.equal(createRes.status, 201, 'an unknown field is dropped, not rejected');

    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner);
    const updateRes = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send(payload);
    assert.equal(updateRes.status, 200);
    const updated = await Property().findById(property._id).lean();

    for (const [field, needle] of Object.entries(sentinels)) {
      assert.equal(locate(created, needle), null, `"${field}" must not be stored on create`);
      assert.equal(locate(updated, needle), null, `"${field}" must not be stored on update`);
    }
  });
});

// ---------------------------------------------------------------------------

test('KNOWN GAP: create does not accept the flat shape that update accepts', async (t) => {
  // Deliberate, not an oversight, and pinned here so it stays deliberate.
  //
  // The two forms serialise differently. add-property builds nested objects
  // (`area`, `address`, `features`, `legal`) whose keys already match the
  // schema, so addProperty needs no per-field translation and has none. The
  // edit form sends its state flat, so updateMyProperty translates.
  //
  // The consequence is that the same JSON body behaves differently on POST and
  // PUT. Nothing ships that shape to POST today, so wiring translation into
  // addProperty now would be speculative work on a path no client uses. But
  // anyone reusing the edit form's payload for creation would lose the values
  // silently, so the asymmetry is recorded rather than left to be rediscovered.
  //
  // Unifying the two is Phase 3B work: it belongs with the create/update
  // contract, not with a defect fix.
  await t.test('the flat names are dropped on create and mapped on update', async () => {
    const payload = {};
    const sentinels = {};
    TRANSIENT_INPUTS.forEach(({ field, path }, i) => {
      const value = field === 'propertyCategory' ? 'Commercial' : sentinelFor(field, i + 900, path);
      payload[field] = value;
      sentinels[field] = Array.isArray(value) ? value[0] : value;
    });

    const { doc: created } = await createProperty(payload);

    const landedOnCreate = TRANSIENT_INPUTS
      .map(({ field }) => field)
      // propertyCategory is read by addProperty for its own bucket logic, so it
      // legitimately shows up; it is not evidence of the flat shape working.
      .filter((f) => f !== 'propertyCategory')
      .filter((f) => locate(created, sentinels[f]));

    assert.deepEqual(
      landedOnCreate, [],
      `create now honours the flat shape for: ${landedOnCreate.join(', ')}. ` +
      `If that was intentional, move these into MUST_PERSIST and delete this test.`
    );
  });
});
