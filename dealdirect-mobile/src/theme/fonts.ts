/**
 * DM Sans. The app's typeface, everywhere.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOW APP-WIDE (changed 2026-08-13)
 *
 * It used to be scoped to Home, as "a one-screen brand statement". That was a
 * mistake, and an obvious one the moment you used the app: Home rendered in DM
 * Sans and every other screen in the platform system face, so moving between
 * tabs looked like moving between two different products. A typeface is not a
 * decoration you apply to your best screen; it is the thing that makes twenty
 * screens read as one app.
 *
 * The cost is real and worth stating. The system faces (SF, Roboto) ship
 * optical sizing and per-size legibility tuning that a single bundled webfont
 * does not have, which is exactly what `typography.ts` originally chose them
 * for. DM Sans has one outline per weight. We accept slightly less refined
 * rendering at the extremes in exchange for the app looking like itself.
 *
 * Keyed by weight rather than by usage, so any `typography` token resolves its
 * face by reading its own `fontWeight` — see `ui/Text.tsx`. Provided once at
 * the root layout; nothing else needs to know.
 */

export const dmSans = {
  '400': 'DMSans_400Regular',
  '500': 'DMSans_500Medium',
  '600': 'DMSans_600SemiBold',
  '700': 'DMSans_700Bold',
} as const;

export type DMSansWeight = keyof typeof dmSans;

/** Passed to `useFonts` in the root layout. */
export { DMSans_400Regular, DMSans_500Medium, DMSans_600SemiBold, DMSans_700Bold } from '@expo-google-fonts/dm-sans';
