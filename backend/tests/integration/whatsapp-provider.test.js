/**
 * Phase 0 (F5): the WhatsApp provider switch.
 *
 * With nothing configured, sends are refused without a network call. With
 * Meta configured, the send goes to the Cloud API endpoint shape (asserted
 * against the loopback fake, which records the path and body). With WAHA
 * configured and no preference, WAHA still wins, so nothing changes for the
 * deployment that has it today.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders, sentMessages, clearMessages, providerBaseUrl } from './setup/fakeProviders.js';

import { activeProvider, sendWhatsAppMessage, isMetaConfigured } from '../../services/whatsappService.js';

const KEYS = ['WHATSAPP_PROVIDER', 'META_WA_PHONE_NUMBER_ID', 'META_WA_ACCESS_TOKEN', 'META_WA_BASE_URL', 'META_WA_API_VERSION', 'WAHA_API_URL', 'WAHA_API_KEY'];
const saved = {};

test.before(async () => { await request(); });
test.beforeEach(async () => {
  await truncateAll();
  clearMessages();
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
});
test.afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

test('provider selection', async (t) => {
  await t.test('nothing configured: none, and the send is refused offline', async () => {
    assert.equal(activeProvider(), 'none');
    const r = await sendWhatsAppMessage('9876543210', 'hi');
    assert.equal(r.success, false);
    assert.equal(sentMessages().length, 0);
  });

  await t.test('Meta configured wins by default; an explicit "waha" without WAHA is none', async () => {
    process.env.META_WA_PHONE_NUMBER_ID = '12345';
    process.env.META_WA_ACCESS_TOKEN = 'tok';
    assert.equal(isMetaConfigured(), true);
    assert.equal(activeProvider(), 'meta');
    process.env.WHATSAPP_PROVIDER = 'waha';
    assert.equal(activeProvider(), 'none');
  });

  await t.test('WAHA alone stays WAHA, so the current deployment is unchanged', () => {
    process.env.WAHA_API_URL = 'http://127.0.0.1:1/waha';
    process.env.WAHA_API_KEY = 'k';
    assert.equal(activeProvider(), 'waha');
  });
});

test('Meta send shape', async (t) => {
  await t.test('a text send posts to /{version}/{phoneNumberId}/messages with the Cloud API body', async () => {
    process.env.META_WA_PHONE_NUMBER_ID = '555000';
    process.env.META_WA_ACCESS_TOKEN = 'secret-token';
    process.env.META_WA_API_VERSION = 'v20.0';
    process.env.META_WA_BASE_URL = providerBaseUrl().replace(/\/pushsms$/, '');

    const r = await sendWhatsAppMessage('98765 43210', 'Your visit is tomorrow');
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(r.provider, 'meta');
    const last = sentMessages().at(-1);
    assert.equal(last.path, '/v20.0/555000/messages');
    assert.equal(last.to, '919876543210', 'Indian mobile normalised with the country code, no @c.us');
  });

  await t.test('a template send carries the template name and parameters', async () => {
    process.env.META_WA_PHONE_NUMBER_ID = '555000';
    process.env.META_WA_ACCESS_TOKEN = 'secret-token';
    process.env.META_WA_BASE_URL = providerBaseUrl().replace(/\/pushsms$/, '');

    const r = await sendWhatsAppMessage('9876543210', 'ignored', { template: { name: 'visit_reminder', params: ['Sat 11am'] } });
    assert.equal(r.success, true);
    assert.equal(sentMessages().at(-1).to, '919876543210');
  });

  await t.test('an invalid phone never reaches the network', async () => {
    process.env.META_WA_PHONE_NUMBER_ID = '555000';
    process.env.META_WA_ACCESS_TOKEN = 'secret-token';
    const r = await sendWhatsAppMessage('12', 'hi');
    assert.equal(r.success, false);
    assert.equal(sentMessages().length, 0);
  });
});
