import { router, type Href } from 'expo-router';

import { PREF_KEYS, prefsStorage } from '@/storage';

/**
 * What the user was trying to do when the app asked them to sign in.
 *
 * ---------------------------------------------------------------------------
 * THE PROBLEM THIS EXISTS FOR
 *
 * A guest opens a listing, reads it, decides, and presses "I'm interested".
 * The app sends them to login — correctly, the enquiry needs an account — and
 * on success drops them on the Search tab. The listing is gone. They now have
 * to remember what it was called and find it again, having already done the
 * only part of this that required thought.
 *
 * That was `login.tsx`'s `router.replace('/(tabs)')`, and it was the same for
 * register and for OTP verification. The website has a pending-interest resume
 * path; this app lost it.
 *
 * ---------------------------------------------------------------------------
 * WHY IT PERSISTS TO DISK
 *
 * The obvious implementation is a module variable, and it is wrong for the one
 * flow that most needs this: registering as an owner sends an SMS OTP, and
 * reading an SMS means leaving the app. On a low-memory Android device the app
 * can be killed while the user is in Messages. An in-memory intent dies there,
 * which is exactly the case the feature is for.
 *
 * So it is written to `prefsStorage`, with a short expiry — an intent is a
 * sentence the user started, not a preference, and one restored an hour later
 * would be the app doing something they no longer remember asking for.
 *
 * ---------------------------------------------------------------------------
 * SINGLE USE
 *
 * `consume` reads and clears in one step. Anything else leaves an intent that
 * fires again the next time the user signs in, which is worse than not having
 * one: it would reopen an enquiry sheet on a listing they dealt with days ago.
 */

export type PendingIntent =
  /** Open a listing and raise its enquiry confirmation. */
  | { kind: 'enquire'; propertyId: string }
  /** Open a unit and raise its booking or enquiry sheet. */
  | { kind: 'unit'; unitTypeId: string; intent: 'booking' | 'enquiry' }
  /** Resume a reward claim reached from a notification. */
  | { kind: 'claimReward'; verificationId: string }
  /** Return to a screen with nothing to re-fire. */
  | { kind: 'open'; propertyId: string }
  /** Return to a deal (a push tap on a lapsed session). Nothing re-fires. */
  | { kind: 'deal'; leadId: string }
  /** Return to the review form for a verified close. Nothing re-fires. */
  | { kind: 'review'; verificationId: string };

interface StoredIntent {
  intent: PendingIntent;
  /** Epoch ms. */
  createdAt: number;
}

/**
 * Fifteen minutes.
 *
 * Long enough to cover leaving the app for an SMS, a password reset email, or
 * a slow OTP; short enough that a session resumed the next morning does not
 * silently reopen something. The owner-registration OTP itself is the longest
 * leg and its own resend cooldown is 45 seconds.
 */
const MAX_AGE_MS = 15 * 60 * 1000;

/** Mirrored in memory so the common path does not touch disk twice. */
let cached: StoredIntent | null | undefined;

function read(): StoredIntent | null {
  if (cached !== undefined) return cached;

  const raw = prefsStorage.getString(PREF_KEYS.pendingIntent);
  if (!raw) {
    cached = null;
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as StoredIntent;
    if (typeof parsed?.createdAt !== 'number' || typeof parsed?.intent?.kind !== 'string') {
      cached = null;
      return null;
    }
    cached = parsed;
    return parsed;
  } catch {
    prefsStorage.remove(PREF_KEYS.pendingIntent);
    cached = null;
    return null;
  }
}

/**
 * Records what to come back to. Call immediately BEFORE routing to login.
 *
 * Overwrites rather than queueing: there is one user doing one thing, and a
 * stack of intents would resume the oldest first, which is never what was
 * meant.
 */
export function setPendingIntent(intent: PendingIntent): void {
  const stored: StoredIntent = { intent, createdAt: Date.now() };
  cached = stored;
  prefsStorage.set(PREF_KEYS.pendingIntent, JSON.stringify(stored));
}

export function clearPendingIntent(): void {
  cached = null;
  prefsStorage.remove(PREF_KEYS.pendingIntent);
}

/**
 * Reads and clears. Call once, on the success path of an auth screen.
 *
 * Returns null when there is nothing pending or the intent has expired, and
 * the caller falls back to its normal destination.
 */
export function consumePendingIntent(): PendingIntent | null {
  const stored = read();
  if (!stored) return null;

  clearPendingIntent();

  if (Date.now() - stored.createdAt > MAX_AGE_MS) return null;
  return stored.intent;
}

/**
 * Where an intent resumes.
 *
 * The `resume` param is what tells the destination screen to re-fire the
 * action rather than merely render. Screens validate it against their own
 * expected values; a param they do not recognise is ignored, so a stale link
 * degrades to "open the screen", never to an unexpected side effect.
 */
export function hrefForPendingIntent(intent: PendingIntent): Href {
  switch (intent.kind) {
    case 'enquire':
      return { pathname: '/property/[id]', params: { id: intent.propertyId, resume: 'enquire' } };
    case 'unit':
      return {
        pathname: '/projects/unit/[unitTypeId]',
        params: { unitTypeId: intent.unitTypeId, resume: intent.intent },
      };
    case 'claimReward':
      return {
        pathname: '/claim-reward/[verificationId]',
        params: { verificationId: intent.verificationId },
      };
    case 'open':
      return { pathname: '/property/[id]', params: { id: intent.propertyId } };
    case 'deal':
      return { pathname: '/deal/[leadId]', params: { leadId: intent.leadId } };
    case 'review':
      return {
        pathname: '/review/[verificationId]',
        params: { verificationId: intent.verificationId },
      };
  }
}

/**
 * The one line every auth screen ends on.
 *
 * `replace`, not `push`, so the back gesture from the resumed screen does not
 * return to a login form the user has already satisfied — which was the
 * behaviour before this existed and is the reason all three screens used
 * `replace` to begin with.
 *
 * Kept here rather than in each screen so login, register and OTP cannot drift
 * apart: the OTP screen is the end of the owner-registration flow and the one
 * most likely to be forgotten, and it is also the flow where the app was most
 * likely to have been killed mid-way.
 */
export function resumeAfterAuth(): void {
  const intent = consumePendingIntent();
  router.replace(intent ? hrefForPendingIntent(intent) : '/(tabs)');
}
