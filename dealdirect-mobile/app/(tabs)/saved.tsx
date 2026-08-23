import { Redirect } from 'expo-router';

/**
 * `/(tabs)/saved` — kept as a redirect, not deleted.
 *
 * Saved became Activity on 2026-08-24: the same interested list and saved
 * searches, plus a shortlist and bookings, under a name that describes the
 * user's hunt rather than one storage bucket in it.
 *
 * The path survives for `dealdirect://` links already in the wild. It stays
 * inside `(tabs)` rather than moving to the stack because that is where it
 * was; a route that changes GROUP changes URL shape, which is the thing a
 * redirect exists to avoid. It is registered `href: null` in the tab layout,
 * so it redirects without ever drawing a fifth tab.
 */
export default function SavedRedirect() {
  return <Redirect href="/(tabs)/activity" />;
}
