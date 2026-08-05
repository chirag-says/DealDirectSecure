import '../global.css';
import 'react-native-gesture-handler';

import { QueryClientProvider } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useState } from 'react';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { createQueryClient } from '@/api';
import { AuthProvider } from '@/auth';
import { ThemeProvider } from '@/theme';

/**
 * Root layout and provider stack.
 *
 * Order matters:
 *   GestureHandlerRootView  must wrap anything using a gesture
 *   SafeAreaProvider        must sit above anything reading insets
 *   QueryClientProvider     must sit above AuthProvider, which clears the cache
 *   AuthProvider            must sit above every screen that reads the session
 *
 * The query client is created in state rather than at module scope so a Fast
 * Refresh does not swap it for a new one mid-session and drop the cache.
 */
export default function RootLayout() {
  const [queryClient] = useState(createQueryClient);

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <AuthProvider>
              <StatusBar style="auto" />
              {/*
                Only routes needing non-default options are declared. Every
                other file under app/ is picked up automatically.

                `property` and `chat` were declared here in M1 and warned on
                every render: neither is a route node. Without an
                `app/property/_layout.tsx` the children register under their own
                full names (`property/[id]/index`, `property/[id]/gallery`,
                `property/[id]/map`, `chat/[conversationId]`), so the parent
                names matched nothing and their options were discarded. They
                also asked for `presentation: 'card'`, which is already the
                default, so the declarations were inert even in principle.
                Removed rather than propped up with layout files that exist only
                to make a no-op valid. M4 can add `app/property/_layout.tsx` if
                it wants gallery and map nested under the detail screen.
              */}
              <Stack screenOptions={{ headerShown: false }}>
                <Stack.Screen name="index" />
                <Stack.Screen name="(auth)" />
                <Stack.Screen name="(tabs)" />
              </Stack>
            </AuthProvider>
          </ThemeProvider>
        </QueryClientProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
