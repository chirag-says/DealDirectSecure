import type * as HapticsModule from 'expo-haptics';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * Haptic feedback, in the app's own vocabulary.
 *
 * ---------------------------------------------------------------------------
 * WHY A THIN NAMED LAYER RATHER THAN CALLING expo-haptics DIRECTLY
 *
 * `Haptics.impactAsync(ImpactFeedbackStyle.Light)` at a call site says HOW, not
 * WHY, and the two drift: the day the design decides a shortlist tap should
 * feel heavier, every call site has to be found and changed. Naming the
 * MEANINGS — a selection, a confirmation, a warning — keeps that decision in
 * one file and keeps the screens reading in intent.
 *
 * ---------------------------------------------------------------------------
 * FIRE AND FORGET, ALWAYS
 *
 * Every function here is void and swallows its own errors. A haptic is a
 * garnish on an interaction that has already happened; a phone with a broken
 * vibrator, a host without the module, or a device with haptics disabled in
 * system settings must never turn "you tapped save" into an exception. The
 * promise from expo-haptics is deliberately not awaited and not returned.
 *
 * Absent module degrades to nothing, through `optionalNativeModule` — the same
 * reason the image picker is loaded that way. A build without it simply has no
 * haptics, which is the correct silent failure for a garnish.
 */

const Haptics = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-haptics') as typeof HapticsModule,
  'expo-haptics',
  'Haptic feedback is unavailable in this host.'
);

function safe(run: () => Promise<unknown>): void {
  try {
    // Intentionally not awaited. See the module doc.
    void run().catch(() => {});
  } catch {
    // The synchronous throw path — a missing enum, a torn-down module.
  }
}

/**
 * A light tick, for choosing something.
 *
 * Shortlisting, toggling a filter chip, switching a tab — anything where the
 * user picked one option among several. The lightest of the three so it can be
 * used often without becoming noise.
 */
export function selection(): void {
  if (!Haptics) return;
  safe(() => Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light));
}

/**
 * A firmer tap, for committing to something.
 *
 * Pressing the raised Post action, opening a sheet that begins a real flow.
 * Between `selection` and `success` in weight: more than a pick, less than a
 * completed transaction.
 */
export function press(): void {
  if (!Haptics) return;
  safe(() => Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium));
}

/**
 * The double-buzz of something completing.
 *
 * An enquiry sent, a reward revealed, a booking confirmed. Reserved for genuine
 * completions, because a success pattern fired on an ordinary tap is the fastest
 * way to make a user turn haptics off.
 */
export function success(): void {
  if (!Haptics) return;
  safe(() => Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success));
}

/** The stutter of a refusal — a failed submit, a rejected input. */
export function warning(): void {
  if (!Haptics) return;
  safe(() => Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning));
}

/** Whether this host can produce haptics at all. Rarely needed — the functions
 *  above are safe to call regardless — but useful for a settings toggle. */
export const hapticsAvailable = Haptics !== null;
