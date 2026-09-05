/**
 * The one-time handover of a device-local shortlist to the server.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A PURE FUNCTION AND NOT THREE LINES IN A HOOK
 *
 * The decision has four inputs and exactly one chance to be right. Getting it
 * wrong in either direction is bad in a way the user notices:
 *
 *   merging twice   resurrects listings the user deliberately deleted from
 *                   their shortlist on another device, silently, at sign-in.
 *   not merging     loses everything a guest saved before they had an account,
 *                   which is the entire population of first-time users.
 *
 * So the decision is separated from the effect, and the effect does nothing
 * the decision did not already authorise. `merge.test.ts` covers it.
 *
 * ---------------------------------------------------------------------------
 * THE GUARD IS PER ACCOUNT, PER INSTALL
 *
 * `prefsStorage` (not user-scoped storage) holds the ids of accounts this
 * install has already handed a list to, so a second account on the same phone
 * gets its own handover, and a logout does not re-arm the first one.
 *
 * Known and accepted gap: if a user signs out, saves a few listings as a
 * guest, and signs back into the SAME account, those saves are not merged
 * automatically. Re-arming the guard would mean re-uploading whatever is local
 * whenever a session appears, and after a successful handover the local list
 * is cleared, so anything still local at that point is either a guest-era save
 * or something the server already refused. Resurrecting deleted rows is the
 * worse of the two failures; the user can re-save from the listing, and the
 * button says what it did.
 *
 * ---------------------------------------------------------------------------
 * THE CAP
 *
 * The server accepts 200 ids per merge and the local store holds at most 200,
 * so the two agree by construction. The slice here is belt and braces against
 * a store written by an older build with a higher ceiling: truncating the
 * OLDEST is the same trim the store already applies, so the rows a user is
 * most likely to still care about are the ones that survive.
 */

export const MERGE_CAP = 200;

export type MergeSkipReason =
  | 'no-session'
  /** This account already had its handover on this install. */
  | 'already-merged'
  | 'nothing-local';

export interface MergeDecision {
  shouldMerge: boolean;
  /** Exactly what to send. Empty whenever `shouldMerge` is false. */
  propertyIds: string[];
  /** Present only when `shouldMerge` is false. */
  skipReason?: MergeSkipReason;
  /** True when the local list was longer than the server will accept. */
  truncated: boolean;
}

export interface MergeInput {
  /** The signed-in account, or null while a guest or during the session probe. */
  userId: string | null | undefined;
  localIds: readonly string[];
  /** Accounts this install has already handed a list to. */
  mergedFor: readonly string[];
}

/**
 * Decides whether to hand the local list over, and what to send.
 *
 * Order matters: the session is checked before the guard, so a guest never
 * reads as "already merged", and the guard before the emptiness check, so an
 * account that has already merged is reported as such rather than as having
 * nothing to send. Both distinctions are what the caller logs.
 */
export function decideMerge({ userId, localIds, mergedFor }: MergeInput): MergeDecision {
  if (!userId) {
    return { shouldMerge: false, propertyIds: [], skipReason: 'no-session', truncated: false };
  }

  if (mergedFor.includes(userId)) {
    return { shouldMerge: false, propertyIds: [], skipReason: 'already-merged', truncated: false };
  }

  const unique = dedupe(localIds);

  if (unique.length === 0) {
    return { shouldMerge: false, propertyIds: [], skipReason: 'nothing-local', truncated: false };
  }

  return {
    shouldMerge: true,
    propertyIds: unique.slice(0, MERGE_CAP),
    truncated: unique.length > MERGE_CAP,
  };
}

/**
 * Duplicates and blanks removed, first occurrence kept.
 *
 * The store cannot produce a duplicate, but the store is not the only thing
 * that has ever written that MMKV key, and a merge payload with the same id
 * twice would count once as added and once as skipped, making the numbers in
 * the toast wrong for no reason.
 */
function dedupe(ids: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];

  for (const id of ids) {
    if (typeof id !== 'string') continue;
    const trimmed = id.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

/**
 * The guard list, after a successful handover.
 *
 * Append-only and deduped. Kept small deliberately: an install that has hosted
 * more accounts than this has bigger problems than a stale guard, and an
 * unbounded list in preferences is a slow leak nobody ever looks at.
 */
export const MAX_TRACKED_ACCOUNTS = 8;

export function rememberMerged(mergedFor: readonly string[], userId: string): string[] {
  if (mergedFor.includes(userId)) return [...mergedFor];
  return [...mergedFor, userId].slice(-MAX_TRACKED_ACCOUNTS);
}

/** Parses whatever is in preferences into a list of account ids. */
export function readMergedFor(raw: string | undefined): string[] {
  if (!raw) return [];

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((id): id is string => typeof id === 'string' && id.length > 0);
  } catch {
    return [];
  }
}
