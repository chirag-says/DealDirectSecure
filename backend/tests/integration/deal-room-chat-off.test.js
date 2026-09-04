/**
 * Phase 2: with CHAT_ENABLED unset the deal room still works, and the
 * messaging wall answers with a code the clients can act on.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { ownerWithSession, buyerWithSession, makeProperty, makeLead } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

test('messaging is a 503 with a code when chat is off; the deal itself is unaffected', async () => {
  const o = await ownerWithSession(api);
  const b = await buyerWithSession(api);
  const property = await makeProperty(o.owner);
  const lead = await makeLead(property, b.buyer);

  const chat = await withClient(api.post(`/api/deals/${lead._id}/conversation`), { cookies: b.cookies }).send({});
  assert.equal(chat.status, 503);
  assert.equal(chat.body.code, 'CHAT_DISABLED');

  const view = await withClient(api.get(`/api/deals/${lead._id}`), { cookies: b.cookies });
  assert.equal(view.status, 200);
  assert.equal(view.body.data.chatEnabled, false);
  assert.equal(view.body.data.agreementsEnabled, false);
  assert.equal(view.body.data.conversation, null);

  const chatRoute = await withClient(api.get('/api/chat/conversations'), { cookies: b.cookies });
  assert.equal(chatRoute.status, 404, 'the chat router is not mounted');
});
