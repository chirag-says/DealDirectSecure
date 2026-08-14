/**
 * How long ago, in prose.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT THE `timeAgo` IN `ConversationRow` / `NotificationRow`
 *
 * Those two return "3d" and "12m" — a terse form for a tight metadata slot at
 * the right edge of a row, where the label has to fit beside a name and a
 * preview line. This returns "3 days ago", the form a listing card and the
 * property detail screen want, where the phrase is the whole of what that line
 * says and abbreviating it saves nothing.
 *
 * The same information in two registers is two functions, not one function with
 * a mode flag. A flag would put the choice at every call site and get it wrong
 * about as often as it got it right.
 *
 * ---------------------------------------------------------------------------
 * WHY IT DEGRADES TO A DATE
 *
 * "437 days ago" is a number the reader has to convert before it means
 * anything. Past a month, an actual date is both shorter and more useful, which
 * is what every portal does with an old listing.
 *
 * Returns null rather than a placeholder when the input is missing or
 * unparseable. `createdAt` is optional on `PropertySummary` and the caller's
 * correct response to its absence is to render nothing, not to render "—".
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

export function relativeDay(iso: string | undefined): string | null {
  if (!iso) return null;

  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return null;

  // Clamped at zero. Server and device clocks disagree by a few seconds often
  // enough that an unclamped difference produces "in 4 seconds" on a listing
  // posted this instant, which reads as a bug rather than as a clock skew.
  const elapsed = Math.max(0, Date.now() - then);

  if (elapsed < HOUR) return 'just now';
  if (elapsed < DAY) {
    const hours = Math.floor(elapsed / HOUR);
    return hours === 1 ? 'an hour ago' : `${hours} hours ago`;
  }

  const days = Math.floor(elapsed / DAY);
  if (days === 1) return 'yesterday';
  if (elapsed < WEEK) return `${days} days ago`;

  if (elapsed < 5 * WEEK) {
    const weeks = Math.floor(elapsed / WEEK);
    return weeks === 1 ? 'last week' : `${weeks} weeks ago`;
  }

  return new Date(iso).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
}

/** True for the first week, which is what a "New" marker means on a listing. */
export function isRecent(iso: string | undefined, withinDays = 7): boolean {
  if (!iso) return false;

  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return false;

  const elapsed = Date.now() - then;
  return elapsed >= 0 && elapsed < withinDays * DAY;
}
