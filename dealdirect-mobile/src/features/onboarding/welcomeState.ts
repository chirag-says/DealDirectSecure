import { PREF_KEYS, prefsStorage } from '@/storage';

export { resolveEntryRoute, type EntryRoute } from './entryRoute';

/**
 * Where a cold start lands (2026-09-05).
 *
 *   signed in                      → the app, straight away
 *   signed out, first time here    → the welcome screen, with Skip
 *   signed out, has been here      → the app, as a guest
 *
 * "Has been here" is a device fact, recorded the first time the welcome
 * screen is dismissed by any of its three exits (Log in, Create account,
 * Skip). It is not cleared on logout: a person who signed out has been
 * introduced already, and the ordinary login screen is the one they want
 * next, not the tour.
 *
 * The decision table itself lives in `entryRoute.ts`, import-free, so it is
 * unit-tested without the native storage module. These two helpers are the
 * only side effects.
 */

export function hasSeenWelcome(): boolean {
  return prefsStorage.getString(PREF_KEYS.welcomeSeen) === '1';
}

export function markWelcomeSeen(): void {
  prefsStorage.set(PREF_KEYS.welcomeSeen, '1');
}

/** The permissions primer (`app/setup.tsx`) has been dismissed on this install. */
export function hasSeenSetup(): boolean {
  return prefsStorage.getString(PREF_KEYS.setupSeen) === '1';
}

export function markSetupSeen(): void {
  prefsStorage.set(PREF_KEYS.setupSeen, '1');
}
