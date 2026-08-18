/**
 * Measure the Phase 4.10 and 4.11 quick wins against dealdirect_dev.
 *
 *   node scripts/verify-phase4-quickwins-dev.mjs
 *
 * 4.11 is measured by counting real Mongo commands against the `subcategories`
 * collection while driving the property read endpoints. 4.10 is measured by
 * counting `Set-Cookie` headers across a representative request mix.
 *
 * Read-only: every request is a GET, and the run asserts the database is
 * unchanged rather than assuming it.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import supertest from 'supertest';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
process.env.NODE_ENV = 'development';

const { app } = await import('../server.js');
await new Promise((r) => setTimeout(r, 1500));

const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName}\n`);
if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  process.exit(1);
}

const api = supertest(app);
const Property = mongoose.model('Property');

const baseline = { properties: await Property.countDocuments() };
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

// ---------------------------------------------------------------------------
// 4.11 — count commands issued against `subcategories`
// ---------------------------------------------------------------------------

const perCollection = {};
mongoose.connection.on('commandStarted', () => {});
mongoose.set('debug', (collection, method) => {
  perCollection[collection] = (perCollection[collection] || 0) + 1;
  void method;
});

const resetCounts = () => { for (const k of Object.keys(perCollection)) delete perCollection[k]; };

const READ_ENDPOINTS = [
  ['home feed', '/api/properties/property-list'],
  ['public list', '/api/properties/list'],
  ['search', '/api/properties/search?q=a'],
];

console.log('4.11 — queries against the retired `subcategories` collection');
{
  let totalSub = 0;
  for (const [label, path] of READ_ENDPOINTS) {
    resetCounts();
    const res = await api.get(path);
    const sub = perCollection.subcategories || 0;
    totalSub += sub;
    console.log(`    ${label.padEnd(14)} status=${res.status}  subcategories queries=${sub}` +
      `  properties=${perCollection.properties || 0}` +
      `  categories=${perCollection.categories || 0}` +
      `  propertytypes=${perCollection.propertytypes || 0}`);
  }
  check('no read path queries `subcategories`', totalSub === 0, `total=${totalSub}`);

  // MEASURED, AND IT CORRECTS THE BASELINE. This count was ALSO zero before the
  // populates were removed. Mongoose skips a populate entirely when no document
  // in the result set has the field set, and zero of 47 properties have ever
  // had a subcategory — so the ten `populate("subcategory")` calls issued no
  // queries at all.
  //
  // 4.11 is therefore a correctness and clarity fix, not a measured query
  // saving. The baseline document claimed "one extra lookup per populated
  // query"; that was wrong, and this run is why. The change still earns its
  // place — it removes a join on a retired relation that WOULD start costing a
  // lookup the moment any document acquired the field — but it should not be
  // reported as a performance improvement.
}

console.log('\n4.11 — the response shape is unchanged apart from the retired field');
{
  const res = await api.get('/api/properties/property-list');
  const first = (res.body?.data || res.body || [])[0];
  if (!first) {
    check('a listing came back to inspect', false, 'no properties returned');
  } else {
    check('category is still populated', typeof first.category === 'object' && first.category !== null,
      JSON.stringify(first.category));
    check('propertyType is still populated',
      typeof first.propertyType === 'object' && first.propertyType !== null,
      JSON.stringify(first.propertyType));
    check('the denormalised names are untouched',
      typeof first.categoryName === 'string' && typeof first.propertyTypeName === 'string',
      `${first.categoryName} / ${first.propertyTypeName}`);
    check('subcategory is absent or an unpopulated null',
      first.subcategory === undefined || first.subcategory === null,
      `value=${JSON.stringify(first.subcategory)}`);
  }
}

// ---------------------------------------------------------------------------
// 4.10 — count Set-Cookie across a representative request mix
// ---------------------------------------------------------------------------

const issues = async (path) => {
  const res = await api.get(path);
  return { path, status: res.status, cookie: (res.headers['set-cookie'] || []).join(';').includes('csrf_token=') };
};

console.log('\n4.10 — where the CSRF cookie is issued');
{
  const rows = await Promise.all([
    issues('/api/categories/list-category'),
    issues('/api/properties/property-list'),
    issues('/api/csrf-token'),
    issues('/health'),
    issues('/uploads/nothing-here.jpg'),
  ]);
  for (const r of rows) {
    console.log(`    ${r.path.padEnd(34)} status=${String(r.status).padEnd(4)} Set-Cookie csrf=${r.cookie}`);
  }
  const api_ = rows.filter((r) => r.path.startsWith('/api'));
  const skipped = rows.filter((r) => !r.path.startsWith('/api'));

  check('every API read still issues the token', api_.every((r) => r.cookie),
    'this is how the double submit is bootstrapped');
  check('static and health do NOT issue it', skipped.every((r) => !r.cookie),
    skipped.map((r) => `${r.path}=${r.cookie}`).join(', '));
  check('/health still answers 200', rows.find((r) => r.path === '/health').status === 200);
}

// ---------------------------------------------------------------------------

const final = { properties: await Property.countDocuments() };
const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
console.log('\nfinal   :', JSON.stringify(final));
console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly (read-only run)');

console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
await mongoose.disconnect();
process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
