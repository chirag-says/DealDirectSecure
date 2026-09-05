import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { DealRole, Visit, VisitStatus } from '../../types/backend/deal';
import {
  isVisitOpen,
  visitActions,
  visitState,
  visitUpdateErrorCopy,
  visitWaitingCopy,
  type VisitControl,
} from './visitState.ts';

/**
 * Every status x role x proposer combination, on both sides of the time
 * boundary. The server refuses a control this table does not offer, so a
 * wrong row here is a button that fails on tap.
 */

const ME = 'me-user';
const THEM = 'them-user';

const NOW = new Date('2026-09-04T10:00:00.000Z');
const FUTURE = '2026-09-05T10:00:00.000Z';
const PAST = '2026-09-03T10:00:00.000Z';

function visit(overrides: Partial<Visit>): Visit {
  return {
    id: 'v1',
    scheduledAt: FUTURE,
    status: 'proposed',
    doneConfirmedBy: [],
    proposedBy: THEM,
    feedback: null,
    createdAt: PAST,
    updatedAt: PAST,
    ...overrides,
  };
}

const ROLES: DealRole[] = ['buyer', 'owner'];

describe('visitActions: proposed', () => {
  for (const role of ROLES) {
    it(`${role}, my proposal, future: cancel only, waiting on them`, () => {
      const state = visitState(visit({ proposedBy: ME }), role, ME, NOW);
      assert.deepEqual(state.controls, ['cancel']);
      assert.equal(state.waiting, 'their_confirmation');
      assert.equal(state.mine, true);
      assert.equal(state.past, false);
    });

    it(`${role}, my proposal, past: cancel only, waiting on nothing`, () => {
      const state = visitState(visit({ proposedBy: ME, scheduledAt: PAST }), role, ME, NOW);
      assert.deepEqual(state.controls, ['cancel']);
      assert.equal(state.waiting, null);
      assert.equal(state.past, true);
    });

    it(`${role}, their proposal, future: confirm or propose another`, () => {
      const state = visitState(visit({ proposedBy: THEM }), role, ME, NOW);
      assert.deepEqual(state.controls, ['confirm', 'propose_another']);
      assert.equal(state.waiting, 'your_confirmation');
      assert.equal(state.mine, false);
    });

    it(`${role}, their proposal, past: propose another only (confirm would be TIME_PASSED)`, () => {
      const state = visitState(visit({ proposedBy: THEM, scheduledAt: PAST }), role, ME, NOW);
      assert.deepEqual(state.controls, ['propose_another']);
      assert.equal(state.waiting, null);
    });
  }

  it('the boundary is scheduledAt itself: exactly then counts as past', () => {
    const at = visit({ proposedBy: THEM, scheduledAt: NOW.toISOString() });
    assert.deepEqual(visitActions(at, 'buyer', ME, NOW), ['propose_another']);
    const oneMsBefore = new Date(NOW.getTime() - 1);
    assert.deepEqual(visitActions(at, 'buyer', ME, oneMsBefore), ['confirm', 'propose_another']);
  });
});

describe('visitActions: confirmed', () => {
  for (const role of ROLES) {
    for (const proposedBy of [ME, THEM]) {
      const who = proposedBy === ME ? 'mine' : 'theirs';

      it(`${role}, ${who}, before the time: cancel only`, () => {
        const state = visitState(visit({ status: 'confirmed', proposedBy }), role, ME, NOW);
        assert.deepEqual(state.controls, ['cancel']);
        assert.equal(state.waiting, 'the_visit');
      });

      it(`${role}, ${who}, after the time: done, no-show, cancel`, () => {
        const state = visitState(
          visit({ status: 'confirmed', proposedBy, scheduledAt: PAST }),
          role,
          ME,
          NOW
        );
        assert.deepEqual(state.controls, ['done', 'no_show', 'cancel']);
        assert.equal(state.waiting, null);
      });
    }
  }
});

describe('visitActions: done', () => {
  it('owner who has not marked done: confirm it happened', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [THEM] }),
      'owner',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, ['confirm_done']);
    assert.equal(state.waiting, 'your_done');
    assert.equal(state.iMarkedDone, false);
    assert.equal(state.bothDone, false);
  });

  it('owner who marked done, waiting on the buyer: nothing to press', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [ME] }),
      'owner',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, []);
    assert.equal(state.waiting, 'their_done');
  });

  it('owner, both done: nothing to press, nothing waiting', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [ME, THEM] }),
      'owner',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, []);
    assert.equal(state.waiting, null);
    assert.equal(state.bothDone, true);
  });

  it('buyer who has not marked done and has no feedback: both controls', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [THEM] }),
      'buyer',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, ['confirm_done', 'feedback']);
  });

  it('buyer who marked done, no feedback yet: feedback only', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [ME] }),
      'buyer',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, ['feedback']);
  });

  it('buyer with feedback given, both done: nothing', () => {
    const state = visitState(
      visit({
        status: 'done',
        scheduledAt: PAST,
        doneConfirmedBy: [ME, THEM],
        feedback: 'interested',
      }),
      'buyer',
      ME,
      NOW
    );
    assert.deepEqual(state.controls, []);
  });

  it('owner never gets the feedback control', () => {
    const state = visitState(
      visit({ status: 'done', scheduledAt: PAST, doneConfirmedBy: [ME, THEM] }),
      'owner',
      ME,
      NOW
    );
    assert.equal(state.controls.includes('feedback'), false);
  });

  it('tolerates a missing doneConfirmedBy', () => {
    const broken = visit({ status: 'done', scheduledAt: PAST });
    (broken as { doneConfirmedBy?: string[] }).doneConfirmedBy = undefined;
    assert.deepEqual(visitActions(broken, 'owner', ME, NOW), ['confirm_done']);
  });
});

describe('visitActions: terminal statuses and unknowns', () => {
  const terminal: VisitStatus[] = ['no_show', 'cancelled'];
  for (const status of terminal) {
    for (const role of ROLES) {
      for (const proposedBy of [ME, THEM]) {
        it(`${status}, ${role}, ${proposedBy === ME ? 'mine' : 'theirs'}: nothing`, () => {
          const state = visitState(visit({ status, proposedBy }), role, ME, NOW);
          assert.deepEqual(state.controls, []);
          assert.equal(state.waiting, null);
        });
      }
    }
  }

  it('an unknown status offers nothing rather than throwing', () => {
    const odd = visit({ status: 'rescheduled' as VisitStatus });
    assert.deepEqual(visitActions(odd, 'buyer', ME, NOW), []);
  });

  it('an unparseable scheduledAt is treated as not past', () => {
    const odd = visit({ scheduledAt: 'not-a-date', proposedBy: THEM });
    assert.deepEqual(visitActions(odd, 'buyer', ME, NOW), ['confirm', 'propose_another']);
  });
});

describe('isVisitOpen', () => {
  it('proposed and confirmed occupy the open slot; the rest do not', () => {
    assert.equal(isVisitOpen({ status: 'proposed' }), true);
    assert.equal(isVisitOpen({ status: 'confirmed' }), true);
    assert.equal(isVisitOpen({ status: 'done' }), false);
    assert.equal(isVisitOpen({ status: 'no_show' }), false);
    assert.equal(isVisitOpen({ status: 'cancelled' }), false);
  });
});

describe('visitUpdateErrorCopy', () => {
  it('has a line per server code and falls back to the given message', () => {
    for (const code of [
      'OWN_PROPOSAL',
      'NOT_PROPOSED',
      'TIME_PASSED',
      'NOT_OPEN',
      'TOO_EARLY',
      'ALREADY_CONFIRMED',
      'DEAL_CLOSED',
      'VISIT_NOT_DONE',
      'FEEDBACK_GIVEN',
      'BUYER_ONLY',
    ]) {
      assert.notEqual(visitUpdateErrorCopy(code, 'fallback'), 'fallback', code);
    }
    assert.equal(visitUpdateErrorCopy('SOMETHING_NEW', 'fallback'), 'fallback');
    assert.equal(visitUpdateErrorCopy(undefined, 'fallback'), 'fallback');
  });
});

describe('visitWaitingCopy', () => {
  it('names the counterpart and returns null for nothing', () => {
    assert.equal(visitWaitingCopy('their_confirmation', 'Asha'), 'Waiting for Asha to confirm');
    assert.equal(visitWaitingCopy('your_confirmation', 'Asha'), 'Asha proposed this time');
    assert.equal(visitWaitingCopy(null, 'Asha'), null);
  });
});

// The control union is closed; a new member must be handled by VisitCard.
const ALL_CONTROLS: VisitControl[] = [
  'confirm',
  'cancel',
  'propose_another',
  'done',
  'no_show',
  'confirm_done',
  'feedback',
];
void ALL_CONTROLS;
