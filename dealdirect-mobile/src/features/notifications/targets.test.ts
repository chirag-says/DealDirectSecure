import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { AppNotification } from '../../types/backend/notification';
import {
  hrefForTarget,
  NOTIFICATION_KINDS,
  readNotificationKind,
  resolveNotificationTarget,
  resolveTargetFromData,
} from './targets.ts';

/**
 * The resolver is the one gate between server-controlled text and
 * navigation, so every branch is pinned here: each kind resolves to exactly
 * its target, every id is checked as an ObjectId, an unknown kind is nothing,
 * and `actionUrl` is consulted for one shape only.
 */

const ID = '5f9d88b3c1a2b3d4e5f60718';
const OTHER = 'aaaaaaaaaaaaaaaaaaaaaaaa';

const notification = (
  overrides: Partial<AppNotification> & { data?: AppNotification['data'] }
): AppNotification => ({
  _id: ID,
  user: ID,
  title: 't',
  message: 'm',
  type: 'general',
  data: {},
  isRead: false,
  createdAt: '2026-09-04T00:00:00.000Z',
  updatedAt: '2026-09-04T00:00:00.000Z',
  ...overrides,
});

describe('resolveTargetFromData: every kind', () => {
  it('property needs a propertyId', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'property', propertyId: ID }), {
      kind: 'property',
      id: ID,
    });
    assert.equal(resolveTargetFromData({ kind: 'property' }), null);
  });

  it('leads needs nothing', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'leads' }), { kind: 'leads' });
  });

  it('dealReward needs a verificationId', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'dealReward', verificationId: ID }), {
      kind: 'dealReward',
      verificationId: ID,
    });
    assert.equal(resolveTargetFromData({ kind: 'dealReward' }), null);
  });

  it('savedSearches lands on the list with or without an id', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'savedSearches', savedSearchId: ID }), {
      kind: 'savedSearches',
    });
    assert.deepEqual(resolveTargetFromData({ kind: 'savedSearches' }), { kind: 'savedSearches' });
  });

  it('deal and visit both resolve to the deal by leadId', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'deal', leadId: ID }), {
      kind: 'deal',
      leadId: ID,
    });
    assert.deepEqual(resolveTargetFromData({ kind: 'visit', leadId: ID, visitId: OTHER }), {
      kind: 'deal',
      leadId: ID,
    });
    assert.equal(resolveTargetFromData({ kind: 'visit', visitId: OTHER }), null);
  });

  it('message needs a conversationId and carries leadId when present', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'message', conversationId: ID }), {
      kind: 'message',
      conversationId: ID,
    });
    assert.deepEqual(
      resolveTargetFromData({ kind: 'message', conversationId: ID, leadId: OTHER }),
      { kind: 'message', conversationId: ID, leadId: OTHER }
    );
    assert.equal(resolveTargetFromData({ kind: 'message', leadId: OTHER }), null);
  });

  it('review needs a verificationId; a reviewId alone is not a route', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'review', verificationId: ID }), {
      kind: 'review',
      verificationId: ID,
    });
    assert.equal(resolveTargetFromData({ kind: 'review', reviewId: ID }), null);
  });

  it('digest needs nothing', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'digest' }), { kind: 'digest' });
  });

  it('every kind in the vocabulary has a branch', () => {
    for (const kind of NOTIFICATION_KINDS) {
      const target = resolveTargetFromData({
        kind,
        propertyId: ID,
        verificationId: ID,
        leadId: ID,
        conversationId: ID,
      });
      assert.notEqual(target, null, kind);
    }
  });
});

describe('resolveTargetFromData: refusals', () => {
  it('unknown kind is nothing', () => {
    assert.equal(resolveTargetFromData({ kind: 'chat', conversationId: ID }), null);
    assert.equal(resolveTargetFromData({ kind: 'Property', propertyId: ID }), null);
    assert.equal(resolveTargetFromData({ kind: '' }), null);
  });

  it('non-object payloads are nothing', () => {
    assert.equal(resolveTargetFromData(undefined), null);
    assert.equal(resolveTargetFromData(null), null);
    assert.equal(resolveTargetFromData('property'), null);
    assert.equal(resolveTargetFromData(42), null);
  });

  it('invalid ids are rejected in every position', () => {
    const bad = ['', '123', 'zzzzzzzzzzzzzzzzzzzzzzzz', `${ID}0`, { $oid: ID }, 12345, null];
    for (const value of bad) {
      assert.equal(resolveTargetFromData({ kind: 'property', propertyId: value }), null);
      assert.equal(resolveTargetFromData({ kind: 'dealReward', verificationId: value }), null);
      assert.equal(resolveTargetFromData({ kind: 'deal', leadId: value }), null);
      assert.equal(resolveTargetFromData({ kind: 'message', conversationId: value }), null);
      assert.equal(resolveTargetFromData({ kind: 'review', verificationId: value }), null);
    }
  });

  it('a malformed leadId on a message drops the leadId, not the message', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'message', conversationId: ID, leadId: 'x' }), {
      kind: 'message',
      conversationId: ID,
    });
  });

  it('ids are trimmed but not otherwise repaired', () => {
    assert.deepEqual(resolveTargetFromData({ kind: 'property', propertyId: ` ${ID} ` }), {
      kind: 'property',
      id: ID,
    });
  });

  it('actionUrl is never consulted by the kind resolver', () => {
    assert.equal(
      resolveTargetFromData({ kind: 'property', actionUrl: `/properties/${ID}` }),
      null
    );
    assert.equal(resolveTargetFromData({ actionUrl: `/properties/${ID}` }), null);
  });
});

describe('readNotificationKind', () => {
  it('returns the kind only when it is in the vocabulary', () => {
    assert.equal(readNotificationKind({ kind: 'deal' }), 'deal');
    assert.equal(readNotificationKind({ kind: 'chat' }), undefined);
    assert.equal(readNotificationKind({ kind: 7 }), undefined);
    assert.equal(readNotificationKind(null), undefined);
  });
});

describe('resolveNotificationTarget: kind first, then the older heuristics', () => {
  it('prefers data.kind over type', () => {
    const row = notification({ type: 'interest', data: { kind: 'deal', leadId: ID } });
    assert.deepEqual(resolveNotificationTarget(row), { kind: 'deal', leadId: ID });
  });

  it('falls back to type when kind is absent or unresolvable', () => {
    assert.deepEqual(
      resolveNotificationTarget(notification({ type: 'interest', data: { propertyId: ID } })),
      { kind: 'leads' }
    );
    assert.deepEqual(
      resolveNotificationTarget(
        notification({ type: 'deal_reward', data: { kind: 'dealReward', verificationId: ID } })
      ),
      { kind: 'dealReward', verificationId: ID }
    );
    assert.deepEqual(
      resolveNotificationTarget(
        notification({ type: 'deal_reward', data: { verificationId: ID } })
      ),
      { kind: 'dealReward', verificationId: ID }
    );
  });

  it('reads a property id from the one actionUrl shape it recognises', () => {
    assert.deepEqual(
      resolveNotificationTarget(notification({ data: { actionUrl: `/properties/${ID}` } })),
      { kind: 'property', id: ID }
    );
    assert.deepEqual(
      resolveNotificationTarget(
        notification({ data: { actionUrl: `https://dealdirect.in/property/${ID}?utm=x` } })
      ),
      { kind: 'property', id: ID }
    );
  });

  it('follows no other actionUrl', () => {
    const urls = [
      'javascript:alert(1)',
      'file:///etc/passwd',
      'https://evil.example/',
      `/deal/${ID}`,
      `/review/${ID}`,
      `/chat/${ID}`,
      '/owner/leads',
      '/notifications',
      `/properties/${ID.slice(0, 23)}`,
    ];
    for (const actionUrl of urls) {
      assert.equal(resolveNotificationTarget(notification({ data: { actionUrl } })), null, actionUrl);
    }
  });

  it('a saved-search id alone lands on the list', () => {
    assert.deepEqual(
      resolveNotificationTarget(notification({ data: { savedSearchId: ID } })),
      { kind: 'savedSearches' }
    );
    assert.equal(resolveNotificationTarget(notification({ data: { savedSearchId: 'nope' } })), null);
  });

  it('nothing recognisable is nothing', () => {
    assert.equal(resolveNotificationTarget(notification({ data: {} })), null);
    assert.equal(
      resolveNotificationTarget(notification({ data: { kind: 'digest-ish', foo: 'bar' } })),
      null
    );
  });
});

describe('hrefForTarget', () => {
  it('maps every target to its route', () => {
    assert.equal(hrefForTarget({ kind: 'property', id: ID }), `/property/${ID}`);
    assert.equal(hrefForTarget({ kind: 'leads' }), '/owner/leads');
    assert.equal(hrefForTarget({ kind: 'dealReward', verificationId: ID }), `/claim-reward/${ID}`);
    assert.deepEqual(hrefForTarget({ kind: 'savedSearches' }), {
      pathname: '/(tabs)/activity',
      params: { segment: 'searches' },
    });
    assert.equal(hrefForTarget({ kind: 'deal', leadId: ID }), `/deal/${ID}`);
    assert.equal(hrefForTarget({ kind: 'message', conversationId: ID }), `/chat/${ID}`);
    assert.equal(
      hrefForTarget({ kind: 'message', conversationId: ID, leadId: OTHER }),
      `/deal/${OTHER}`
    );
    assert.equal(hrefForTarget({ kind: 'review', verificationId: ID }), `/review/${ID}`);
    assert.equal(hrefForTarget({ kind: 'digest' }), '/owner/analytics');
  });
});
