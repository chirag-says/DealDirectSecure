import { Redirect } from 'expo-router';

/**
 * `/notifications` — kept as a redirect, not deleted.
 *
 * Notifications moved into the tab bar as Updates on 2026-08-24. This path
 * still has live callers that are not in this codebase and cannot be updated
 * by editing it:
 *
 *   - `dealdirect://notifications` deep links, and any the OS has cached.
 *   - `Notification.data.actionUrl` values already written by the backend and
 *     sitting in users' notification rows.
 *
 * Deleting the file would turn both into `+not-found`. A redirect costs one
 * frame and one file, and `replace` semantics mean the dead path never enters
 * the back stack — pressing back from Updates goes where the user came from,
 * not through here.
 */
export default function NotificationsRedirect() {
  return <Redirect href="/(tabs)/updates" />;
}
