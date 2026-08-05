import { router } from 'expo-router';

import { EmptyState, Screen } from '@/ui';

/**
 * Unmatched route.
 *
 * Reachable from a malformed deep link, so it must offer a way out rather than
 * trapping the user on a dead end.
 */
export default function NotFoundScreen() {
  return (
    <Screen>
      <EmptyState
        title="Page not found"
        description="That link does not point anywhere in the app."
        actionLabel="Go to Explore"
        onAction={() => router.replace('/(tabs)')}
      />
    </Screen>
  );
}
