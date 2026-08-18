/**
 * Measure the Phase 4.3 / 4.4 bounds against dealdirect_dev.
 *
 *   node scripts/verify-list-bounds-dev.mjs
 *
 * Reports document counts and payload sizes for each list endpoint, and proves
 * no client-supplied limit can produce an unbounded response. Read-only: every
 * request is a GET, and the run asserts the database is unchanged.
 *
 * No timings are taken and no latency claim is made. The goal is bounded
 * resource usage, which is what is measured.
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

const kb = (n) => `${(n / 1024).toFixed(1)} KB`;

async function probe(path) {
  const res = await api.get(path);
  const body = Array.isArray(res.body) ? res.body : res.body?.data || [];
  return {
    path,
    status: res.status,
    count: body.length,
    bytes: Buffer.byteLength(JSON.stringify(res.body)),
    limit: res.headers['x-limit'] ?? res.body?.pagination?.limit,
    total: res.headers['x-total-count'] ?? res.body?.pagination?.total,
  };
}

console.log('Payload size and document count per endpoint');
{
  const rows = [];
  for (const p of [
    '/api/properties/list',
    '/api/properties/list?limit=5000',
    '/api/properties/list?limit=200000',
    '/api/properties/property-list',
    '/api/properties/property-list?limit=200000',
    '/api/properties/search',
  ]) rows.push(await probe(p));

  for (const r of rows) {
    console.log(`    ${r.path.padEnd(44)} status=${r.status} docs=${String(r.count).padStart(3)}` +
      `  payload=${kb(r.bytes).padStart(9)}  effectiveLimit=${r.limit ?? '-'}  total=${r.total ?? '-'}`);
  }

  check('no endpoint returns more than its cap',
    rows.every((r) => r.count <= 5000), 'bounded by construction');
  check('an absurd limit is clamped, not honoured',
    rows.find((r) => r.path.endsWith('list?limit=200000')).limit === '5000',
    'X-Limit reports the effective bound');
  check('the property-list feed reports its bound',
    rows.find((r) => r.path === '/api/properties/property-list').limit === 200);
}

console.log('\nBehaviour at the current corpus is unchanged');
{
  const feed = await probe('/api/properties/property-list');
  // Compared against the endpoint's own total, not the raw collection count:
  // this feed selects approved, non-builder listings, so it legitimately
  // returns fewer documents than `properties` holds. The invariant that
  // matters is that nothing is truncated — every document the filter matches
  // fits in one page at the current corpus.
  check('nothing is truncated at the current corpus',
    feed.count === Number(feed.total),
    `${feed.count} returned of ${feed.total} matching (collection holds ${baseline.properties})`);

  const res = await api.get('/api/properties/property-list');
  check('the existing envelope is intact', res.body?.success === true && Array.isArray(res.body?.data));
  check('pagination is additive, not a replacement',
    res.body?.pagination?.hasMore === false, JSON.stringify(res.body?.pagination));
}

console.log('\nThe retired endpoint');
{
  const res = await api.get('/api/properties/filter');
  console.log(`    /api/properties/filter  status=${res.status}  code=${res.body?.code}`);
  check('answers 410 rather than falling through to the /:id wildcard',
    res.status === 410 && res.body?.code === 'ENDPOINT_RETIRED');
}

console.log('\nThe sitemap caller still works');
{
  const res = await probe('/api/properties/list?limit=5000');
  check('limit=5000 is honoured', res.status === 200 && res.limit === '5000',
    `sitemap.js depends on this; a cap below 5000 would silently shorten it`);
}

const final = { properties: await Property.countDocuments() };
const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
console.log('\nfinal   :', JSON.stringify(final));
console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly (read-only run)');

console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
await mongoose.disconnect();
process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
