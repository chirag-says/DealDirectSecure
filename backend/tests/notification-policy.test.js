/**
 * Channel policy invariants (Phase 0, engine E1).
 *
 * The policy table is data; these tests pin the promises the clients and the
 * budget depend on, so a retuned row cannot silently withhold an email people
 * used to get or route a kind the apps do not know.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { NOTIFICATION_POLICY, policyFor, WEEKLY_CAP } from '../services/notificationService.js';

const PRE_EXISTING = ['general', 'interest', 'saved-search-match', 'deal_verification', 'deal_reward'];
const KINDS = new Set(['property', 'leads', 'dealReward', 'savedSearches', 'deal', 'visit', 'message', 'review', 'digest', null]);

describe('policy table', () => {
  test('every pre-existing type still emails as before', () => {
    for (const type of PRE_EXISTING) {
      assert.equal(NOTIFICATION_POLICY[type].email, 'always', `${type} must keep emailing`);
    }
  });

  test('every row uses a kind the clients understand', () => {
    for (const [type, row] of Object.entries(NOTIFICATION_POLICY)) {
      assert.ok(KINDS.has(row.kind), `${type} routes to unknown kind ${row.kind}`);
      assert.ok(['always', 'capped', 'never'].includes(row.email), `${type} email mode`);
      assert.equal(typeof row.push, 'boolean');
      assert.equal(typeof row.whatsapp, 'boolean');
      assert.equal(typeof row.critical, 'boolean');
    }
  });

  test('WhatsApp is reserved for journey-critical events', () => {
    for (const [type, row] of Object.entries(NOTIFICATION_POLICY)) {
      if (row.whatsapp) assert.equal(row.critical, true, `${type} sends WhatsApp but is not critical`);
    }
  });

  test('an unknown type gets the default: in-app + push + email, no WhatsApp', () => {
    const row = policyFor('something-new');
    assert.equal(row.push, true);
    assert.equal(row.email, 'always');
    assert.equal(row.whatsapp, false);
    assert.equal(row.kind, null);
  });

  test('the weekly cap is small and positive', () => {
    assert.ok(WEEKLY_CAP >= 1 && WEEKLY_CAP <= 5);
  });

  test('the table is frozen', () => {
    assert.throws(() => { NOTIFICATION_POLICY.general = {}; }, TypeError);
    assert.throws(() => { NOTIFICATION_POLICY.general.push = false; }, TypeError);
  });
});

describe('every type a controller writes has a policy row', () => {
  const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
  const files = [
    '../controllers/propertyController.js',
    '../controllers/adminController.js',
    '../controllers/dealController.js',
    '../controllers/chatController.js',
    '../controllers/agreementController.js',
    '../jobs/visitReminders.js',
    '../jobs/ownerWeeklyDigest.js',
  ];

  test('no controller invents a type the policy does not know', () => {
    const unknown = [];
    for (const rel of files) {
      const src = stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));
      for (const m of src.matchAll(/type:\s*["']([a-z_-]+)["']/g)) {
        const type = m[1];
        // `type:` is also a key on suggestions, payments, messages and
        // reports. Those values are excluded by name; a NEW notification type
        // would still surface here because it would not be in this list.
        if (['text', 'system', 'message', 'property', 'template', 'project', 'locality', 'city', 'unknown'].includes(type)) continue;
        if (!NOTIFICATION_POLICY[type]) unknown.push(`${rel}: ${type}`);
      }
    }
    assert.deepEqual(unknown, []);
  });
});
