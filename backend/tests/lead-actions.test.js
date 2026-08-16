/**
 * Lead actions wiring (Phase 2.7)
 *
 * Two working, IDOR-guarded endpoints had no caller, so `isViewed` was false on
 * every lead forever and `contactHistory` was always empty. That made
 * `unreadLeads` permanently equal to the total lead count and left the "new
 * lead" dot on every card.
 *
 * No new endpoints. These assert the existing contracts are unchanged and that
 * the frontend now calls them.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §13 F-L14.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Lead from '../models/Lead.js';

const stripComments = (src) =>
  src.replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '').replace(new RegExp('//[^\\r\\n]*', 'g'), '');

const readBackend = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const CLIENT = new URL('../../client-next/src/', import.meta.url);
const readClient = (rel) => readFileSync(new URL(rel, CLIENT), 'utf8');

const leadController = readBackend('../controllers/leadController.js');
const leadRoutes = readBackend('../routes/leadRoutes.js');
const dashboard = readClient('app/my-properties/MyPropertiesContent.jsx');
const dashboardCode = stripComments(dashboard);

const fnBody = (src, name) => {
  const start = src.indexOf(`export const ${name}`);
  const next = src.indexOf('\nexport const ', start + 10);
  return src.slice(start, next === -1 ? src.length : next);
};

describe('the endpoints exist and were not modified', () => {
  test('no new lead endpoints were added', () => {
    const routes = (leadRoutes.match(/router\.(get|post|put|patch|delete)\(/g) || []).length;
    assert.equal(routes, 7, `lead route count changed to ${routes} — 2.7 must add none`);
  });

  test('mark-viewed is still PUT /:id/viewed', () => {
    assert.match(leadRoutes, /router\.put\("\/:id\/viewed", validateMongoId\('id'\), markLeadViewed\)/);
  });

  test('contact history is still POST /:id/contact', () => {
    assert.match(leadRoutes, /router\.post\("\/:id\/contact", validateContactHistory, addContactHistory\)/);
  });
});

describe('only the lead owner can perform these actions', () => {
  for (const fn of ['markLeadViewed', 'addContactHistory']) {
    const body = fnBody(leadController, fn);

    test(`${fn} verifies ownership against the database record`, () => {
      assert.match(
        body,
        /lead\.propertyOwner\.toString\(\) !== ownerId\.toString\(\)/,
        `${fn} lost its IDOR guard`
      );
      assert.match(body, /status\(403\)/);
    });

    test(`${fn} loads the lead before deciding`, () => {
      const loadAt = body.indexOf('Lead.findById(leadId)');
      const checkAt = body.indexOf('lead.propertyOwner.toString()');
      assert.ok(loadAt !== -1 && checkAt !== -1);
      assert.ok(loadAt < checkAt, 'ownership must be read from the record, not trusted from input');
    });

    test(`${fn} rejects a malformed lead id`, () => {
      assert.match(body, /ObjectId\.isValid\(leadId\)/);
    });

    test(`${fn} logs the IDOR attempt`, () => {
      assert.match(body, /IDOR attempt/);
    });
  }

  test('both routes sit behind authMiddleware', () => {
    assert.match(leadRoutes, /router\.use\(authMiddleware\)|authMiddleware/);
  });
});

describe('opening a lead marks it viewed', () => {
  test('the dashboard calls the mark-viewed endpoint', () => {
    assert.match(
      dashboardCode,
      /api\.put\(`\/leads\/\$\{leadId\}\/viewed`\)/,
      'PUT /leads/:id/viewed still has no caller'
    );
  });

  test('opening a lead card triggers it', () => {
    assert.match(dashboardCode, /onView\?\.\(lead\._id\)/);
    assert.match(dashboardCode, /onView=\{handleMarkLeadViewed\}/);
  });

  test('it fires on open, not on render', () => {
    // Marking every lead read as the list mounts would defeat the indicator.
    assert.doesNotMatch(dashboardCode, /useEffect\([^)]*onView/);
    assert.match(dashboardCode, /if \(!showActions\) onView\?\.\(lead\._id\)/);
  });

  test('an already-read lead sends no request', () => {
    const handler = dashboardCode.slice(dashboardCode.indexOf('const handleMarkLeadViewed'));
    assert.match(handler.slice(0, 900), /if \(!lead \|\| lead\.isViewed\) return/);
  });

  test('the server sets both isViewed and viewedAt', () => {
    const body = fnBody(leadController, 'markLeadViewed');
    assert.match(body, /isViewed: true/);
    assert.match(body, /viewedAt: new Date\(\)/);
  });

  test('both fields exist on the schema', () => {
    assert.ok(Lead.schema.path('isViewed'));
    assert.ok(Lead.schema.path('viewedAt'));
    assert.equal(Lead.schema.path('isViewed').options.default, false);
  });
});

describe('the unread count decreases', () => {
  test('the dashboard decrements unreadLeads when a lead is opened', () => {
    const handler = dashboardCode.slice(dashboardCode.indexOf('const handleMarkLeadViewed'));
    assert.match(handler.slice(0, 1200), /unreadLeads: Math\.max\(0, \(prev\.unreadLeads \|\| 0\) - 1\)/);
  });

  test('it cannot go negative', () => {
    const handler = dashboardCode.slice(dashboardCode.indexOf('const handleMarkLeadViewed'));
    assert.match(handler.slice(0, 1200), /Math\.max\(0,/);
  });

  test('the lead row is updated locally so the dot clears', () => {
    const handler = dashboardCode.slice(dashboardCode.indexOf('const handleMarkLeadViewed'));
    assert.match(handler.slice(0, 1200), /isViewed: true/);
  });

  test('the analytics count is still derived from isViewed server-side', () => {
    // The number was always real; nothing ever set the flag it counts.
    assert.match(leadController, /unreadLeads/);
    assert.match(leadController, /isViewed: false/);
  });
});

describe('a contact action records history', () => {
  test('the dashboard calls the contact endpoint', () => {
    assert.match(
      dashboardCode,
      /api\.post\(`\/leads\/\$\{leadId\}\/contact`, \{ action \}\)/,
      'POST /leads/:id/contact still has no caller'
    );
  });

  test('all three contact channels are wired', () => {
    for (const action of ['call', 'email', 'whatsapp']) {
      assert.match(
        dashboardCode,
        new RegExp(`onContact\\?\\.\\(lead\\._id, '${action}'\\)`),
        `the ${action} action does not record contact history`
      );
    }
  });

  test('onContact is actually passed to the card', () => {
    // It was declared in the LeadCard signature and never supplied.
    assert.match(dashboardCode, /onContact=\{handleLeadContact\}/);
  });

  test('contacting also marks the lead viewed', () => {
    const handler = dashboardCode.slice(dashboardCode.indexOf('const handleLeadContact'));
    assert.match(handler.slice(0, 900), /handleMarkLeadViewed\(leadId\)/);
  });

  test('the server appends rather than replacing history', () => {
    const body = fnBody(leadController, 'addContactHistory');
    assert.match(body, /\$push:/);
    assert.doesNotMatch(body, /\$set:\s*\{\s*contactHistory/);
  });

  test('the action is required and length-capped', () => {
    const body = fnBody(leadController, 'addContactHistory');
    assert.match(body, /Action is required/);
    assert.match(body, /substring\(0, 100\)/);
    assert.match(body, /substring\(0, 1000\)/);
  });

  test('contactHistory is on the schema', () => {
    assert.ok(Lead.schema.path('contactHistory'));
  });
});

describe('existing lead status behaviour is unchanged', () => {
  test('the status enum is untouched', () => {
    assert.deepEqual(Lead.schema.path('status').options.enum, [
      'new', 'contacted', 'interested', 'negotiating', 'converted', 'lost',
    ]);
    assert.equal(Lead.schema.path('status').options.default, 'new');
  });

  test('addContactHistory still advances the lead to contacted', () => {
    // Pre-existing server behaviour, deliberately preserved: this is the
    // automatic transition that was designed and never fired, because nothing
    // called the endpoint.
    const body = fnBody(leadController, 'addContactHistory');
    assert.match(body, /\$set: \{ status: 'contacted' \}/);
  });

  test('the manual status endpoint is unchanged', () => {
    assert.match(leadRoutes, /router\.put\("\/:id\/status", validateLeadStatusUpdate, updateLeadStatus\)/);
    assert.match(dashboardCode, /api\.put\(`\/leads\/\$\{leadId\}\/status`, \{ status \}\)/);
  });

  test('no lead state machine was introduced (that is Phase 3)', () => {
    assert.doesNotMatch(leadController, /LEAD_STATUS_TRANSITIONS|ILLEGAL_TRANSITION/);
  });

  test('the status badge still renders all six statuses', () => {
    for (const s of ['new', 'contacted', 'interested', 'negotiating', 'converted', 'lost']) {
      assert.match(dashboardCode, new RegExp(`\\b${s}:`), `LeadStatusBadge lost "${s}"`);
    }
  });
});

describe('failures do not disrupt the owner', () => {
  /**
   * Slice one handler only.
   *
   * A fixed character window overruns into the next handler —
   * handleUpdateLeadStatus legitimately toasts on failure, so a loose window
   * reads that as this handler's behaviour.
   */
  const handlerBody = (name) => {
    const start = dashboardCode.indexOf(`const ${name}`);
    assert.notEqual(start, -1, `${name} not found`);
    const next = dashboardCode.indexOf('\n  const handle', start + 10);
    return dashboardCode.slice(start, next === -1 ? dashboardCode.length : next);
  };

  test('a failed mark-viewed is not surfaced as an error', () => {
    const block = handlerBody('handleMarkLeadViewed');
    assert.match(block, /catch/);
    assert.doesNotMatch(block, /toast\.error/, 'a read-receipt failure must not interrupt the owner');
  });

  test('a failed contact log does not claim the call failed', () => {
    const block = handlerBody('handleLeadContact');
    assert.match(block, /catch/);
    assert.doesNotMatch(block, /toast\.error/, 'the dialler already opened; the task succeeded');
  });

  test('status updates DO still surface failures', () => {
    // The contrast that makes the two above deliberate rather than sloppy: a
    // failed status change is a user action that did not take effect.
    assert.match(handlerBody('handleUpdateLeadStatus'), /toast\.error/);
  });
});
