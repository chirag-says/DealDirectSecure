import { Image as ExpoImage } from 'expo-image';
import { useRouter } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useCallback } from 'react';
import { StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { HERO_BG, HERO_GLASS, HERO_GLASS_BORDER, HERO_TEXT, HERO_TEXT_FAINT, HERO_TEXT_MUTED } from '@/features/home/heroTheme';
import { markWelcomeSeen } from '@/features/onboarding';
import { radius, screenPadding, spacing, useTheme } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';

/**
 * The first-launch welcome (2026-09-05).
 *
 * Shown once per install, to a person who has never signed in on this
 * device, immediately after the launch motion. Three exits, each of which
 * marks the install as introduced so this screen never returns:
 *
 *   Log in            → the ordinary login screen
 *   Create an account → the ordinary registration screen
 *   Skip for now      → the app, as a guest, with everything a guest can do
 *
 * THIS IS NOT THE LOGIN SCREEN and must not grow into one. The auth screens
 * are forms on `AuthShell`, reached from many places, with a back affordance
 * and no photograph. This is a single greeting on the hero artwork with the
 * proposition in one line and the way in. The two share nothing but the
 * brand, on purpose: a returning guest who taps "Log in" from Profile must
 * not land on a tour.
 *
 * Skip is the third button, not a corner glyph, because the reference apps
 * in this market put it there and because a person who wants to look before
 * committing should not have to hunt for permission to.
 */
export default function WelcomeScreen() {
  const router = useRouter();
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  const leave = useCallback(
    (href: '/(auth)/login' | '/(auth)/register' | '/(tabs)') => {
      markWelcomeSeen();
      // Every exit passes through the permissions primer once, and the
      // primer carries the chosen destination on to where it was going.
      router.replace({ pathname: '/setup', params: { next: href } });
    },
    [router]
  );

  return (
    <View style={{ flex: 1, backgroundColor: HERO_BG }}>
      <StatusBar style="light" />

      <ExpoImage
        source={require('../assets/home/brand/hero-dusk.webp')}
        style={StyleSheet.absoluteFill}
        contentFit="cover"
        contentPosition="right center"
        cachePolicy="memory"
      />
      {/* The photograph's own slab already darkens the lower left; this
          settles the whole lower half so the copy and the buttons sit on one
          reliable ground whatever the screen's aspect ratio crops to. */}
      <Gradient
        colors={['rgba(11, 13, 18, 0.35)', 'rgba(11, 13, 18, 0)', 'rgba(11, 13, 18, 0.85)', HERO_BG]}
        locations={[0, 0.25, 0.62, 0.9]}
        style={StyleSheet.absoluteFillObject}
      />

      <View
        style={{
          flex: 1,
          paddingTop: insets.top + spacing.lg,
          paddingBottom: insets.bottom + spacing.lg,
          paddingHorizontal: screenPadding,
        }}
      >
        <ExpoImage
          source={require('../assets/home/brand/logo.png')}
          style={{ width: 168, height: Math.round((168 * 82) / 308) }}
          contentFit="contain"
          accessibilityLabel="DealDirect"
          cachePolicy="memory"
        />
        <Text variant="footnote" style={{ color: HERO_TEXT_MUTED, marginTop: 4 }}>
          Zero Brokerage Property Deals
        </Text>

        <View style={{ flex: 1 }} />

        <Text
          variant="display"
          accessibilityRole="header"
          style={{ color: HERO_TEXT, fontWeight: '700', lineHeight: 44 }}
        >
          {'Property,\ndirect from owners'}
        </Text>
        <Text variant="body" style={{ color: HERO_TEXT_MUTED, marginTop: spacing.sm, maxWidth: 320 }}>
          No brokerage, no middleman. Search, shortlist and talk to owners yourself.
        </Text>

        <View style={{ gap: spacing.sm, marginTop: spacing.xl }}>
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Log in"
            onPress={() => leave('/(auth)/login')}
            activeScale={0.97}
            style={{ ...styles.button, backgroundColor: theme.colors.brand }}
          >
            <Text variant="bodyEmphasis" style={{ color: HERO_TEXT }}>
              Log in
            </Text>
          </PressableScale>

          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Create an account"
            onPress={() => leave('/(auth)/register')}
            activeScale={0.97}
            style={{ ...styles.button, backgroundColor: HERO_GLASS, borderWidth: 1, borderColor: HERO_GLASS_BORDER }}
          >
            <Text variant="bodyEmphasis" style={{ color: HERO_TEXT }}>
              Create an account
            </Text>
          </PressableScale>

          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Skip for now and browse as a guest"
            onPress={() => leave('/(tabs)')}
            activeScale={0.97}
            style={{ ...styles.button, backgroundColor: 'transparent' }}
          >
            <Text variant="bodyEmphasis" style={{ color: HERO_TEXT_MUTED }}>
              Skip for now
            </Text>
          </PressableScale>
        </View>

        <Text variant="caption" style={{ color: HERO_TEXT_FAINT, textAlign: 'center', marginTop: spacing.md }}>
          By continuing you agree to our{' '}
          <Text
            variant="caption"
            style={{ color: HERO_TEXT_MUTED, textDecorationLine: 'underline' }}
            onPress={() => router.push('/legal/terms')}
            accessibilityRole="link"
          >
            Terms
          </Text>
          {' and '}
          <Text
            variant="caption"
            style={{ color: HERO_TEXT_MUTED, textDecorationLine: 'underline' }}
            onPress={() => router.push('/legal/privacy')}
            accessibilityRole="link"
          >
            Privacy policy
          </Text>
          .
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  button: {
    height: 56,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: radius.full,
  },
});
