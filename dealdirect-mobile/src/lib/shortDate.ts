/**
 * "3 Sep", and "3 Sep 2025" when it was not this year.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT `toLocaleDateString(..., { month: 'short' })`
 *
 * `Intl` is not stable across the places this app runs. Node under `en-IN`
 * abbreviates September as "Sept"; Hermes on an Android build without full ICU
 * abbreviates it differently again, and on some builds falls back to the
 * English default whatever locale is asked for. A three-letter month is not
 * worth a per-platform surprise, and it is definitely not worth a test that
 * passes on a laptop and fails on a phone.
 *
 * `features/properties/priceIntelligence.ts` carries its own copy of this
 * table deliberately: it must stay importable by `node --test`, which means no
 * path aliases and no runtime imports at all. This one is for everything that
 * runs only inside the app.
 */

const MONTHS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
] as const;

/** Null for anything unparseable, rather than the string "Invalid Date". */
export function formatShortDay(value: string | Date | null | undefined, now = new Date()): string | null {
  if (!value) return null;

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;

  const day = `${date.getDate()} ${MONTHS[date.getMonth()]}`;
  return date.getFullYear() === now.getFullYear() ? day : `${day} ${date.getFullYear()}`;
}
