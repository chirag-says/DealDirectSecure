/**
 * Client-side validation of a proposed visit time, mirroring the server.
 *
 * `POST /deals/:leadId/visits` refuses INVALID_TIME, TIME_IN_PAST and
 * TOO_FAR_AHEAD (60 days). The same three codes are produced here, before the
 * request, so the sheet can say what is wrong next to the field rather than
 * after a round trip; and the same copy table serves the server's answer when
 * it disagrees (clock skew, a slow finger across midnight).
 *
 * Pure TypeScript, no React Native import; see `visitTime.test.ts`.
 */

export const MAX_DAYS_AHEAD = 60;

const DAY_MS = 24 * 60 * 60 * 1000;

export type VisitTimeError = 'INVALID_TIME' | 'TIME_IN_PAST' | 'TOO_FAR_AHEAD';

export function validateVisitTime(scheduledAt: Date, now: Date): VisitTimeError | null {
  const at = scheduledAt.getTime();
  if (!Number.isFinite(at)) return 'INVALID_TIME';
  if (at <= now.getTime()) return 'TIME_IN_PAST';
  if (at > now.getTime() + MAX_DAYS_AHEAD * DAY_MS) return 'TOO_FAR_AHEAD';
  return null;
}

/**
 * Builds a local Date from the sheet's two controls: a `YYYY-MM-DD` day (the
 * `DateField` contract) and an hour and minute. Local time, because the
 * visit happens where the property is and the phone is assumed to be there
 * too; `toISOString()` on the result is what the server receives.
 */
export function composeVisitDate(day: string, hour: number, minute: number): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) return null;
  if (!Number.isInteger(minute) || minute < 0 || minute > 59) return null;

  const [y, m, d] = day.split('-').map(Number) as [number, number, number];
  const date = new Date(y, m - 1, d, hour, minute, 0, 0);
  // `new Date(2026, 1, 31)` silently rolls into March. Reject the roll.
  if (date.getFullYear() !== y || date.getMonth() !== m - 1 || date.getDate() !== d) return null;
  return date;
}

/** Both the local check and the server's refusal render through this. */
export function visitTimeErrorCopy(code: VisitTimeError | string | undefined): string {
  switch (code) {
    case 'TIME_IN_PAST':
      return 'That time has already passed.';
    case 'TOO_FAR_AHEAD':
      return `Pick a time within the next ${MAX_DAYS_AHEAD} days.`;
    case 'INVALID_TIME':
      return 'Pick a day and a time.';
    case 'VISIT_ALREADY_OPEN':
      return 'There is already a visit planned for this deal. Cancel it to propose another.';
    case 'DEAL_CLOSED':
      return 'This deal is closed.';
    default:
      return 'Could not plan the visit. Please try again.';
  }
}
