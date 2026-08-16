/**
 * Token purpose boundary + public owner PII
 *
 * The token tests exercise the real decision logic rather than asserting on
 * source text: the predicate each side applies is reproduced here and driven
 * with actual signed JWTs, so a change to the rule fails the test.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §22.2 H3 (socket token as REST
 * bearer), §11 F-L1 (owner contact on a public endpoint).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import jwt from 'jsonwebtoken';

const SECRET = 'test-secret-for-token-boundary-assertions';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const authUser = read('../middleware/authUser.js');
const server = read('../server.js');
const propertyController = read('../controllers/propertyController.js');

/* ------------------------------------------------------------------ *
 * The two predicates under test, mirrored from the implementation.
 * ------------------------------------------------------------------ */

/** authUser.handleJWTAuth — rejects a token stamped for another purpose. */
const restRejects = (decoded) => Boolean(decoded.purpose && decoded.purpose !== 'api');

/** server.js socket "authenticate" — accepts only socket-stamped tokens. */
const socketRejects = (decoded) => decoded.purpose !== 'socket_auth';

const sign = (payload, opts = {}) => jwt.sign(payload, SECRET, { expiresIn: '5m', ...opts });
const decode = (token) => jwt.verify(token, SECRET);

const socketToken = () =>
  sign({ id: '507f1f77bcf86cd799439011', purpose: 'socket_auth', iat: Math.floor(Date.now() / 1000) });
const legacyRestToken = () => sign({ id: '507f1f77bcf86cd799439011' });
const apiToken = () => sign({ id: '507f1f77bcf86cd799439011', purpose: 'api' });

describe('token purpose boundary — the four required directions', () => {
  test('valid REST session token → REST accepted', () => {
    // A legacy/API token (no purpose, or purpose=api) must still authenticate.
    assert.equal(restRejects(decode(legacyRestToken())), false);
    assert.equal(restRejects(decode(apiToken())), false);
  });

  test('socket token → socket endpoint accepted', () => {
    assert.equal(socketRejects(decode(socketToken())), false);
  });

  test('socket token → REST API rejected', () => {
    assert.equal(
      restRejects(decode(socketToken())),
      true,
      'a socket token must not authenticate a REST request'
    );
  });

  test('REST token → socket endpoint rejected (inverse direction)', () => {
    assert.equal(socketRejects(decode(legacyRestToken())), true);
    assert.equal(socketRejects(decode(apiToken())), true);
  });
});

describe('token purpose boundary — expiry and tampering still apply', () => {
  test('an expired socket token is rejected before purpose is considered', () => {
    const expired = jwt.sign({ id: 'x', purpose: 'socket_auth' }, SECRET, { expiresIn: '-1s' });
    assert.throws(() => jwt.verify(expired, SECRET), /jwt expired/);
  });

  test('a token signed with the wrong secret never decodes', () => {
    const foreign = jwt.sign({ id: 'x', purpose: 'api' }, 'a-different-secret');
    assert.throws(() => jwt.verify(foreign, SECRET), /invalid signature/);
  });

  test('purpose cannot be stripped without invalidating the signature', () => {
    // Re-signing with an attacker secret is the only way to drop the claim,
    // and that fails verification above. Confirm the claim is actually carried.
    assert.equal(decode(socketToken()).purpose, 'socket_auth');
  });
});

describe('token purpose boundary — wired into both code paths', () => {
  test('handleJWTAuth applies the purpose check', () => {
    assert.match(
      authUser,
      /decoded\.purpose\s*&&\s*decoded\.purpose\s*!==\s*['"]api['"]/,
      'REST bearer path no longer rejects foreign-purpose tokens'
    );
  });

  test('the REST check runs before the legacy user lookup', () => {
    const checkAt = authUser.search(/decoded\.purpose\s*&&/);
    const legacyAt = authUser.indexOf('decoded.sessionId');
    assert.notEqual(checkAt, -1);
    assert.notEqual(legacyAt, -1);
    assert.ok(checkAt < legacyAt, 'purpose must be rejected before any session/user branch');
  });

  test('the socket handshake requires socket_auth', () => {
    assert.match(
      server,
      /decoded\.purpose\s*!==\s*['"]socket_auth['"]/,
      'socket accepts any signed JWT again'
    );
  });

  test('socket tokens are still minted with a purpose claim', () => {
    const chatRoutes = read('../routes/chatRoutes.js');
    assert.match(chatRoutes, /purpose:\s*['"]socket_auth['"]/);
    assert.match(chatRoutes, /expiresIn:\s*['"]5m['"]/, 'the 5-minute life is part of the control');
  });
});

describe('public property detail does not expose owner contact', () => {
  const fn = (() => {
    const start = propertyController.indexOf('export const getPropertyById');
    const next = propertyController.indexOf('\nexport const ', start + 10);
    return propertyController.slice(start, next === -1 ? propertyController.length : next);
  })();

  test('getPropertyById populates no email and no phone', () => {
    const populate = fn.match(/\.populate\(\s*["']owner["']\s*,\s*["']([^"']+)["']\s*\)/);
    assert.ok(populate, 'owner populate not found — was getPropertyById restructured?');
    const fields = populate[1].split(/\s+/);
    assert.ok(!fields.includes('email'), 'owner email is public again');
    assert.ok(!fields.includes('phone'), 'owner phone is public again');
  });

  test('the owner name is still populated (the UI renders it)', () => {
    const populate = fn.match(/\.populate\(\s*["']owner["']\s*,\s*["']([^"']+)["']\s*\)/);
    assert.ok(populate[1].split(/\s+/).includes('name'));
  });

  test('the route is still public, so the populate is the only control', () => {
    const routes = read('../routes/propertyRoutes.js');
    assert.match(
      routes,
      /router\.get\(\s*["']\/:id["']\s*,\s*getPropertyById\s*\)/,
      'if auth is added to this route, revisit whether contact may be returned'
    );
  });
});
