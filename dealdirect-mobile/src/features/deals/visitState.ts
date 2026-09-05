/**
 * Which controls a visit offers, given who is looking and when.
 *
 * The server owns every rule (`PUT /deals/:leadId/visits/:visitId` refuses
 * with OWN_PROPOSAL, TIME_PASSED, TOO_EARLY and so on). This function mirrors
 * those rules so a button is not drawn for an action the server will refuse,
 * which is a kindness, not a guard: a refusal that slips through is shown as
 * the server's own message. Mirroring is also why this is pure and tested
 * for every status x role x proposer x time combination.
 *
 * Pure TypeScript, no React Native import; see `visitState.test.ts`.
 */

import type { DealRole, Visit } from '@/types/backend/deal';

export type VisitControl =
  /** Accept the other party's proposed time. */
  | 'confirm'
  /** Cancel an open (proposed or confirmed) visit. */
  | 'cancel'
  /** Cancel this proposal and propose a different time in one gesture. */
  | 'propose_another'
  /** Record that a confirmed visit happened. */
  | 'done'
  /** Record that a confirmed visit did not happen. */
  | 'no_show'
  /** The other party marked it done; agree that it happened. */
  | 'confirm_done'
  /** Buyer only, once: how the visit went. */
  | 'feedback';

/** What the visit is waiting on, for the line above the controls. */
export type VisitWaiting =
  | 'their_confirmation'
  | 'your_confirmation'
  | 'the_visit'
  | 'their_done'
  | 'your_done'
  | null;

export interface VisitState {
  controls: VisitControl[];
  waiting: VisitWaiting;
  /** True when `now` is past `scheduledAt`. */
  past: boolean;
  /** True when the current user proposed it. */
  mine: boolean;
  /** True when the current user has marked it done. */
  iMarkedDone: boolean;
  /** True when both parties have marked it done. */
  bothDone: boolean;
}

/**
 * The server accepts `done` from `scheduledAt` minus 30 minutes. The client
 * boundary is `scheduledAt` itself: half an hour early is a server allowance
 * for clock skew, not a thing to advertise with a button.
 */
export function visitState(visit: Visit, role: DealRole, userId: string, now: Date): VisitState {
  const scheduled = new Date(visit.scheduledAt).getTime();
  const past = Number.isFinite(scheduled) ? now.getTime() >= scheduled : false;
  const mine = visit.proposedBy === userId;
  const confirmedBy = visit.doneConfirmedBy ?? [];
  const iMarkedDone = confirmedBy.includes(userId);
  const bothDone = confirmedBy.length >= 2;

  const base = { past, mine, iMarkedDone, bothDone };

  switch (visit.status) {
    case 'proposed': {
      if (mine) {
        // Only the other party can confirm. Past the time, the proposal is
        // dead (TIME_PASSED) and the only sensible act is to withdraw it.
        return { ...base, controls: ['cancel'], waiting: past ? null : 'their_confirmation' };
      }
      if (past) {
        // Confirming a past proposal is refused; offer a new time instead.
        return { ...base, controls: ['propose_another'], waiting: null };
      }
      return { ...base, controls: ['confirm', 'propose_another'], waiting: 'your_confirmation' };
    }

    case 'confirmed': {
      if (!past) return { ...base, controls: ['cancel'], waiting: 'the_visit' };
      return { ...base, controls: ['done', 'no_show', 'cancel'], waiting: null };
    }

    case 'done': {
      const controls: VisitControl[] = [];
      if (!iMarkedDone) controls.push('confirm_done');
      if (role === 'buyer' && !visit.feedback) controls.push('feedback');
      const waiting: VisitWaiting = bothDone ? null : iMarkedDone ? 'their_done' : 'your_done';
      return { ...base, controls, waiting };
    }

    case 'no_show':
    case 'cancelled':
      return { ...base, controls: [], waiting: null };

    default:
      // A status this build does not know. Show nothing rather than guess.
      return { ...base, controls: [], waiting: null };
  }
}

/** Convenience for callers that only want the buttons. */
export function visitActions(
  visit: Visit,
  role: DealRole,
  userId: string,
  now: Date
): VisitControl[] {
  return visitState(visit, role, userId, now).controls;
}

/**
 * The server's refusal of a visit update, as a line the user can act on.
 * These arise only when the screen's picture of the visit is stale (the
 * other party moved first), which is why each one says what to do next.
 */
export function visitUpdateErrorCopy(code: string | undefined, fallback: string): string {
  switch (code) {
    case 'OWN_PROPOSAL':
      return 'Only the other side can confirm a time you proposed.';
    case 'NOT_PROPOSED':
      return 'This visit is no longer waiting for confirmation.';
    case 'TIME_PASSED':
      return 'That time has passed. Propose another.';
    case 'NOT_OPEN':
      return 'This visit is no longer open.';
    case 'TOO_EARLY':
      return 'You can mark a visit done from 30 minutes before it.';
    case 'ALREADY_CONFIRMED':
      return 'Both sides have already confirmed this visit.';
    case 'DEAL_CLOSED':
      return 'This deal is closed.';
    case 'VISIT_NOT_DONE':
      return 'Feedback opens once the visit is marked done.';
    case 'FEEDBACK_GIVEN':
      return 'You have already given feedback on this visit.';
    case 'BUYER_ONLY':
      return 'Only the buyer gives visit feedback.';
    default:
      return fallback;
  }
}

/** Whether a visit still occupies the deal's single open slot. */
export function isVisitOpen(visit: Pick<Visit, 'status'>): boolean {
  return visit.status === 'proposed' || visit.status === 'confirmed';
}

/**
 * The line above the controls. Kept beside the state machine so the copy and
 * the transitions cannot drift apart; a screen renders it, it does not
 * compose it.
 */
export function visitWaitingCopy(waiting: VisitWaiting, counterpart: string): string | null {
  switch (waiting) {
    case 'their_confirmation':
      return `Waiting for ${counterpart} to confirm`;
    case 'your_confirmation':
      return `${counterpart} proposed this time`;
    case 'the_visit':
      return 'Confirmed';
    case 'their_done':
      return `You marked this done. Waiting for ${counterpart} to confirm it happened.`;
    case 'your_done':
      return `${counterpart} marked this done.`;
    case null:
      return null;
  }
}
