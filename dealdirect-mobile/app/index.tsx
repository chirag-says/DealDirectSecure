import { Redirect } from 'expo-router';
import { ActivityIndicator, View } from 'react-native';

import { useAuth } from '@/auth';

/**
 * Bootstrap gate.
 *
 * Holds while the session is restored from the Keychain and probed against
 * `GET /users/me`, then routes once.
 *
 * Both destinations are `Redirect`, not `router.replace`, so this screen never
 * lands in the history stack: a back gesture from Explore must exit the app,
 * not return to a loading spinner.
 *
 * Guests are sent to the tab shell rather than to login. Browsing properties is
 * public on this backend, and gating the whole app behind a login wall would be
 * a product decision the architecture did not make. Individual protected
 * actions prompt for auth when reached.
 *
 * Deep-link resolution joins here in M12: a cold start into a shared property
 * link must land on that property, not on Explore.
 */
export default function Bootstrap() {
  const { isReady } = useAuth();

  if (!isReady) {
    return (
      <View className="flex-1 items-center justify-center bg-background">
        <ActivityIndicator />
      </View>
    );
  }

  // Both guests and authenticated users land on the tab shell; the difference
  // shows up inside individual screens, not in the entry route.
  return <Redirect href="/(tabs)" />;
}
