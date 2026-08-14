import type NetInfoModule from '@react-native-community/netinfo';
import { useEffect, useState } from 'react';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * Connectivity, for the offline banner (M12).
 *
 * `isInternetReachable` is `null` while NetInfo is still probing (briefly, on
 * launch) — treated as "assume online" rather than flashing an offline banner
 * for the first render of every cold start. `isConnected` alone is not enough:
 * a phone can be associated with a Wi-Fi network with no actual internet
 * (a captive portal, a router with no WAN), which `isInternetReachable`
 * specifically checks for and `isConnected` does not.
 *
 * ---------------------------------------------------------------------------
 * OPTIONAL, AND THIS FILE IS WHY THE HELPER EXISTS
 *
 * NetInfo is not in Expo Go. This module is imported by `lib/index`, which is
 * imported by `ui/OfflineBanner`, which is imported by `ui/index` — the barrel
 * nearly every screen in the app pulls from. A plain top-level import of a
 * missing native module therefore did not disable the offline banner; it took
 * down the root layout, so `AuthProvider` never mounted and every single route
 * failed with "useAuth must be used inside AuthProvider".
 *
 * When NetInfo is absent the hook reports ONLINE and never subscribes. That is
 * the right way to be wrong: the offline banner is an explanation for requests
 * that are already failing, so losing it costs a hint, while a stuck "You are
 * offline" bar over a working app would actively lie.
 */
const NetInfo = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => (require('@react-native-community/netinfo') as { default: typeof NetInfoModule }).default,
  '@react-native-community/netinfo',
  'The offline banner is disabled; the app will always be treated as online.'
);

export function useIsOffline(): boolean {
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    if (!NetInfo) return;

    const unsubscribe = NetInfo.addEventListener((state) => {
      setOffline(state.isConnected === false || state.isInternetReachable === false);
    });
    return unsubscribe;
  }, []);

  return offline;
}
