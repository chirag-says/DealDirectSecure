/**
 * Exercise the API contract the web and Admin clients depend on, against
 * dealdirect_dev.
 *
 *   node scripts/verify-api-client-dev.mjs
 *
 * The clients themselves cannot be imported from here — separate apps, separate
 * node_modules — so this drives the real server the way they drive it: cookie
 * credentials, the `X-CSRF-Token` header read from the `csrf_token` cookie, and
 * the same routes. What it proves is that the contract both clients encode is
 * the contract the server actually honours.
 *
 * Read-only against dealdirect_dev. It creates nothing and deletes nothing, so
 * "baseline restored" is trivially true and is asserted rather than assumed.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import supertest from 'supertest';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';

process.env.NODE_ENV = 'development';
const { app } = await import('../server.js');

await new Promise((r) => setTimeout(r, 1500)); // let the app finish connecting

const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName}\n`);
if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  process.exit(1);
}

const api = supertest(app);
const Property = mongoose.model('Property');
const User = mongoose.model('User');

const baseline = {
  properties: await Property.countDocuments(),
  users: await User.countDocuments(),
};
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

try {
  console.log('Success path — what both clients unwrap');
  {
    const res = await api.get('/api/categories/list-category');
    check('200 on a public list route', res.status === 200, `status=${res.status}`);
    check('body is { success, data } as the helpers expect',
      res.body?.success === true && Array.isArray(res.body?.data),
      `keys=${Object.keys(res.body || {}).join(',')}`);
    check('the canonical taxonomy is served', res.body.data.length === 3,
      res.body.data.map((c) => c.name).join(', '));
  }

  console.log('\nCSRF — the token the clients read and send');
  {
    const res = await api.get('/api/csrf-token');
    const setCookie = (res.headers['set-cookie'] || []).join(';');
    check('the token endpoint responds', res.status === 200, `status=${res.status}`);
    check('it sets a csrf_token cookie', /csrf_token=/.test(setCookie));
    // The body deliberately does NOT carry the token — that is the whole point
    // of the double-submit cookie pattern. Both clients used to read it from
    // the body anyway and got undefined; fixed alongside this script.
    check('the body deliberately omits the token', res.body?.csrfToken === undefined);

    const cookie = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
    const token = decodeURIComponent((cookie.match(/csrf_token=([^;]+)/) || [])[1] || '');
    check('the token is readable from the cookie, as the clients read it', token.length > 0);

    // A guarded mutating route WITHOUT the header must be refused.
    const without = await api.delete('/api/users/me').set('Cookie', cookie).send({ password: 'x' });
    check('a mutating request without X-CSRF-Token is refused',
      without.status === 403 || without.status === 401, `status=${without.status}`);

    // WITH the header it gets past CSRF and fails on auth instead.
    const withHeader = await api.delete('/api/users/me')
      .set('Cookie', cookie).set('X-CSRF-Token', token).send({ password: 'x' });
    check('with the header it reaches auth instead of CSRF',
      withHeader.status === 401, `status=${withHeader.status}`);
  }

  console.log('\nUnauthenticated access');
  {
    const res = await api.get('/api/admin/leads');
    check('an admin route refuses an anonymous caller', res.status === 401, `status=${res.status}`);
    check('the error shape is { success:false, message }',
      res.body?.success === false && typeof res.body?.message === 'string');
  }

  console.log('\nBackend 4xx is a normalised error body');
  {
    const res = await api.get('/api/properties/000000000000000000000000');
    check('4xx returns JSON, not HTML', typeof res.body === 'object' && res.body !== null,
      `status=${res.status}`);
    check('it carries a message the client can surface',
      typeof res.body?.message === 'string' || res.body?.success === false,
      JSON.stringify(res.body).slice(0, 80));
  }

  console.log('\nKNOWN FINDING — malformed input returns 5xx');
  {
    // Recorded, not asserted. A Mongoose CastError on an invalid ObjectId
    // surfaces as a 500, so both clients report "server error" for what is
    // simply a malformed request — and it is 5xx noise in Sentry. Normalising
    // it means changing the global error handler, which touches every route and
    // deserves its own pass with its own tests, not an API-client workstream.
    const res = await api.get('/api/properties/not-a-valid-object-id');
    console.log(`  NOTE  invalid ObjectId -> status=${res.status} (should be 400; tracked separately)`);
  }

  console.log('\nUnknown route');
  {
    const res = await api.get('/api/definitely-not-a-route');
    check('404 rather than a hang or a crash', res.status === 404, `status=${res.status}`);
  }
} finally {
  const final = {
    properties: await Property.countDocuments(),
    users: await User.countDocuments(),
  };
  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('\nfinal   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly (read-only run)');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
}
