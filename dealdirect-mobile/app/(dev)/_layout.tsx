import { Redirect, Stack } from 'expo-router';

import { IS_DEV } from '@/config/env';

/**
 * The development-only route group (Phase 5, store readiness).
 *
 * Expo Router builds its tree from the filesystem, so `app/(dev)/gallery.tsx`
 * is a live route in a production build whether or not anything links to it.
 * It is not linked — but `dealdirect://gallery` resolves, and a component
 * gallery is exactly the kind of surface a store reviewer finds and reads as
 * an unfinished app.
 *
 * Deleting the file was the alternative. It is worth keeping: the gallery is
 * how a designer checks every primitive in both themes on a real device, and
 * that is a genuine use. So the group gets a layout that closes the door
 * instead, in one place, for every route added under `(dev)` from now on.
 *
 * `IS_DEV` is `__DEV__`, which the bundler replaces with a literal at build
 * time, so the redirect branch is unreachable code in a release bundle and
 * the gallery is dropped from it entirely.
 */
export default function DevLayout() {
  if (!IS_DEV) return <Redirect href="/(tabs)" />;

  return <Stack screenOptions={{ headerShown: false }} />;
}
