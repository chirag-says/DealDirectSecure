import '../global.css';
import 'react-native-gesture-handler';

import {
  DMSans_400Regular,
  DMSans_500Medium,
  DMSans_600SemiBold,
  DMSans_700Bold,
} from '@expo-google-fonts/dm-sans';
import { ThemeProvider as NavigationThemeProvider } from '@react-navigation/native';
import { PersistQueryClientProvider } from '@tanstack/react-query-persist-client';
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useCallback, useState } from 'react';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { createQueryClient, PERSIST_MAX_AGE, queryPersister, shouldPersistQuery } from '@/api';
import { AuthProvider } from '@/auth';
import { dmSans, navigationThemes, ThemeProvider, useTheme } from '@/theme';
import { FontOverrideProvider, OfflineBanner, ToastProvider } from '@/ui';

// Held open until DM Sans (loaded for the Home redesign, see `theme/fonts.ts`)
// is ready, so Home never flashes the system face before swapping to it.
void SplashScreen.preventAutoHideAsync();

/**
 * Root layout and provider stack.
 *
 * Order matters:
 *   GestureHandlerRootView    must wrap anything using a gesture
 *   SafeAreaProvider          must sit above anything reading insets
 *   PersistQueryClientProvider must sit above AuthProvider, which clears the cache
 *   AuthProvider              must sit above every screen that reads the session
 *
 * `SocketProvider` and `PushBridge` were removed 2026-08-13. Both existed
 * solely to serve chat, which is unmounted product-wide (HANDOFF §9.1 D2).
 * Leaving them mounted would hold a live socket connection open and ask for
 * notification permission on behalf of a feature with no UI. Both modules
 * remain on disk for whenever messaging returns.
 *
 * The query client is created in state rather than at module scope so a Fast
 * Refresh does not swap it for a new one mid-session and drop the cache.
 *
 * M12: `PersistQueryClientProvider` replaces the plain `QueryClientProvider`
 * and rehydrates the cache from MMKV (`src/api/persistence.ts`) before first
 * paint, so a cold start with no connectivity still shows the last-known
 * properties/projects/leads/etc. rather than a blank loading screen. Chat is
 * excluded — see `shouldPersistQuery`'s doc comment for why.
 */
export default function RootLayout() {
  const [queryClient] = useState(createQueryClient);
  const [fontsLoaded] = useFonts({
    DMSans_400Regular,
    DMSans_500Medium,
    DMSans_600SemiBold,
    DMSans_700Bold,
  });

  const onLayout = useCallback(() => {
    if (fontsLoaded) void SplashScreen.hideAsync();
  }, [fontsLoaded]);

  if (!fontsLoaded) return null;

  return (
    <GestureHandlerRootView style={{ flex: 1 }} onLayout={onLayout}>
      <SafeAreaProvider>
        <PersistQueryClientProvider
          client={queryClient}
          persistOptions={{
            persister: queryPersister,
            maxAge: PERSIST_MAX_AGE,
            dehydrateOptions: { shouldDehydrateQuery: shouldPersistQuery },
          }}
        >
          <ThemeProvider>
            <AuthProvider>
              {/*
                DM Sans for the whole app. This used to be mounted at Home's
                root only, which made every other screen render in the platform
                system face — see `theme/fonts.ts`. One provider here, and every
                `Text` in the tree resolves its own weight.
              */}
              <FontOverrideProvider value={dmSans}>
                {/* Above the Stack so a toast raised by any screen paints over
                    it, and inside the theme so it can read colours. */}
                <ToastProvider>
                  <Navigation />
                  <OfflineBanner />
                </ToastProvider>
              </FontOverrideProvider>
            </AuthProvider>
          </ThemeProvider>
        </PersistQueryClientProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

/**
 * The navigator, and the two pieces of chrome that have to agree with the
 * scheme rather than with the OS.
 *
 * Split into its own component only because it reads `useTheme()`, which is not
 * available in `RootLayout` — that is the component rendering the provider.
 *
 * `NavigationThemeProvider` is the fix for the light strip under the tab dock;
 * `theme/navigationTheme.ts` explains what was showing through and why.
 *
 * The status bar is set from the resolved scheme rather than left on `auto`.
 * `auto` reads the OS appearance, so a user who forces Dark on a phone set to
 * Light got black glyphs on the app's black header.
 */
function Navigation() {
  const theme = useTheme();

  return (
    <NavigationThemeProvider value={navigationThemes[theme.scheme]}>
      <StatusBar style={theme.scheme === 'dark' ? 'light' : 'dark'} />
      {/*
        Only routes needing non-default options are declared. Every other file
        under app/ is picked up automatically.

        `property` and `chat` were declared here in M1 and warned on every
        render: neither is a route node. Without an `app/property/_layout.tsx`
        the children register under their own full names
        (`property/[id]/index`, `property/[id]/gallery`, `property/[id]/map`,
        `chat/[conversationId]`), so the parent names matched nothing and their
        options were discarded. They also asked for `presentation: 'card'`,
        which is already the default, so the declarations were inert even in
        principle. Removed rather than propped up with layout files that exist
        only to make a no-op valid. M4 can add `app/property/_layout.tsx` if it
        wants gallery and map nested under the detail screen.
      */}
      <Stack screenOptions={{ headerShown: false }}>
        <Stack.Screen name="index" />
        <Stack.Screen name="(auth)" />
        <Stack.Screen name="(tabs)" />
      </Stack>
    </NavigationThemeProvider>
  );
}
