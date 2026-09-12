import { Redirect } from 'expo-router';
import { ActivityIndicator, View } from 'react-native';

import { useAuth } from '@/auth';
import { hasSeenSetup, hasSeenWelcome, resolveEntryRoute } from '@/features/onboarding';

/**
 * The entry route. Waits for the session probe, then sends the person to
 * one of two places: the app, or the first-launch welcome. The table that
 * decides is `features/onboarding/entryRoute.ts`, and it is the only thing
 * that decides — nothing else in the app redirects to `/welcome`.
 *
 * While the probe runs, this renders the same white the launch overlay is
 * painting on top of it, so there is nothing to see even if the overlay's
 * timing and the probe's disagree by a frame.
 */
export default function Bootstrap() {
  const { status } = useAuth();

  const route = resolveEntryRoute(status, hasSeenWelcome(), hasSeenSetup());

  if (!route) {
    return (
      <View className="flex-1 items-center justify-center bg-background">
        <ActivityIndicator />
      </View>
    );
  }

  return <Redirect href={route} />;
}
