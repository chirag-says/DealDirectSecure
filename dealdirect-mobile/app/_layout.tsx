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
import { Stack, type ErrorBoundaryProps } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useState } from 'react';
import { Pressable, Text as RNText, ScrollView, View } from 'react-native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { startAnalytics } from '@/analytics';
import { createQueryClient, PERSIST_MAX_AGE, queryPersister, shouldPersistQuery } from '@/api';
import { AuthProvider, PhoneVerificationSheet } from '@/auth';
import { AnimatedSplash } from '@/features/onboarding';
import { PushRouter } from '@/notifications';
import { initSentry, wrapRoot } from '@/observability';
import { dmSans, navigationThemes, ThemeProvider, useTheme } from '@/theme';
import { FontOverrideProvider, OfflineBanner, ToastProvider } from '@/ui';

// Held open until DM Sans (loaded for the Home redesign, see `theme/fonts.ts`)
// is ready, so Home never flashes the system face before swapping to it.
void SplashScreen.preventAutoHideAsync();

// Before anything else can throw. A no-op without `EXPO_PUBLIC_SENTRY_DSN` or
// without the native module; see `observability/sentry.ts`.
initSentry();

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
 *
 * ---------------------------------------------------------------------------
 * THE FONT GATE CANNOT BE ALLOWED TO BE PERMANENT — fixed 2026-08-24
 *
 * This held the splash open and rendered `null` until `useFonts` reported
 * success, and it discarded the hook's error. Any font failure — a corrupt
 * download, an OOM decode on a low-end device — therefore left the splash up
 * over an empty tree with no timeout and no way out. The app simply never
 * opened, and it reported nothing.
 *
 * Waiting for a webfont is a nicety; the app opening is not. So the gate now
 * releases on ANY of three conditions: fonts loaded, the loader reported an
 * error, or `FONT_GATE_MS` elapsed. Missing DM Sans costs the system face for
 * the session, which is a cosmetic regression rather than a dead app.
 */

/**
 * How long the splash may wait on fonts before the app opens without them.
 *
 * Chosen against the failure it guards, not against a typical load: a bundled
 * font resolves in tens of milliseconds, so anything still outstanding at three
 * seconds is not slow, it is broken.
 */
const FONT_GATE_MS = 3000;

function RootLayout() {
  const [queryClient] = useState(createQueryClient);

  // Usage events: the timer, the foreground/background flushes and the first
  // `session_start`. Idempotent, so Fast Refresh cannot stack it.
  useEffect(startAnalytics, []);
  const [fontsLoaded, fontError] = useFonts({
    DMSans_400Regular,
    DMSans_500Medium,
    DMSans_600SemiBold,
    DMSans_700Bold,
  });

  /** The deadline half of the gate. See the note above. */
  const [gateExpired, setGateExpired] = useState(false);

  // The launch motion (features/onboarding/AnimatedSplash) takes over from
  // the native splash the moment the fonts are in, and comes down on its own
  // once its choreography ends. Until then it covers whatever the bootstrap
  // route is deciding underneath.
  const [splashDone, setSplashDone] = useState(false);
  const onSplashDone = useCallback(() => setSplashDone(true), []);

  useEffect(() => {
    const timer = setTimeout(() => setGateExpired(true), FONT_GATE_MS);
    return () => clearTimeout(timer);
  }, []);

  const ready = fontsLoaded || fontError !== null || gateExpired;

  const onLayout = useCallback(() => {
    if (ready) void SplashScreen.hideAsync();
  }, [ready]);

  /*
    Belt and braces: `onLayout` fires on the tree below, so it cannot run while
    that tree is `null`. Hiding here too means the splash comes down even if
    the first layout pass is delayed for a reason we have not thought of.
  */
  useEffect(() => {
    if (ready) void SplashScreen.hideAsync();
  }, [ready]);

  if (!ready) return null;

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
              {/* Push taps become routes here. Renders nothing; needs the
                  auth tree so a tap into a signed-in screen lands on the
                  screen's own sign-in prompt rather than a crash. */}
              <PushRouter />
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
                  {/*
                    The just-in-time phone gate. Mounted once, here, because it
                    is raised by the API layer rather than by a screen: a gated
                    request opens it, waits, and then replays itself.

                    It has to sit ABOVE the Stack so it paints over whatever
                    screen triggered it, and it must never be a route — routing
                    away would lose the listing the user was standing on, which
                    is the exact failure this design exists to prevent. Renders
                    nothing until the backend refuses a gated action.
                  */}
                  <PhoneVerificationSheet />
                  <OfflineBanner />
                  {splashDone ? null : <AnimatedSplash onDone={onSplashDone} />}
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
 * `Sentry.wrap` adds the touch-event and profiling hooks around the root; it
 * is the identity when Sentry did not initialise. Named function above, so
 * the export stays a component expo-router can pick up.
 */
export default wrapRoot(RootLayout);

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
        {/* The first-launch welcome. A fade, because it arrives from under
            the launch motion rather than from a tap. */}
        <Stack.Screen name="welcome" options={{ animation: 'fade', gestureEnabled: false }} />
      </Stack>
    </NavigationThemeProvider>
  );
}

/**
 * The app's last line of defence, picked up by expo-router.
 *
 * There was none. A render throw anywhere below this layout was a red box in
 * development and a hard crash to the home screen in release — no message, no
 * retry, and nothing the user could report beyond "it closed".
 *
 * Deliberately built from plain `react-native` primitives with literal colours
 * rather than from `@/ui` and the theme. This renders precisely when something
 * below has already failed, and the provider stack it would otherwise depend on
 * is a plausible thing to have failed: a boundary that can itself throw for
 * want of a context is not a boundary.
 *
 * `retry` re-mounts the subtree, which recovers the whole class of transient
 * faults — a bad cache entry, a null from a request that has since succeeded —
 * without the user force-quitting. A fault that reproduces just lands here
 * again, which is honest.
 *
 * The message is shown rather than hidden. This is a marketplace handling other
 * people's money and property; "something went wrong" with no detail is what
 * makes a bug report useless, and the string is already on the user's device.
 */
export function ErrorBoundary({ error, retry }: ErrorBoundaryProps) {
  return (
    <View style={{ flex: 1, backgroundColor: '#0A0A0A' }}>
      <ScrollView
        contentContainerStyle={{
          flexGrow: 1,
          justifyContent: 'center',
          padding: 24,
          gap: 12,
        }}
      >
        <RNText style={{ color: '#FFFFFF', fontSize: 22, fontWeight: '700' }}>
          Something went wrong
        </RNText>
        <RNText style={{ color: '#A3A3A3', fontSize: 15, lineHeight: 21 }}>
          This screen could not be displayed. You can try again, and if it keeps
          happening please send us the message below.
        </RNText>

        <View
          style={{
            marginTop: 4,
            padding: 12,
            borderRadius: 12,
            backgroundColor: '#1C1C1C',
          }}
        >
          <RNText style={{ color: '#D4D4D4', fontSize: 13 }}>
            {error?.message ?? 'No further detail is available.'}
          </RNText>
        </View>

        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Try again"
          onPress={retry}
          style={{
            marginTop: 8,
            height: 48,
            borderRadius: 999,
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#F33F40',
          }}
        >
          <RNText style={{ color: '#FFFFFF', fontSize: 16, fontWeight: '700' }}>
            Try again
          </RNText>
        </Pressable>
      </ScrollView>
    </View>
  );
}
