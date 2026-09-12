import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { router } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import React from 'react';
import { ScrollView, StyleSheet, View, useWindowDimensions } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import {
  HERO_HEADER_GLASS,
  HERO_HEADER_INK,
  HERO_TEXT,
  HERO_TEXT_MUTED,
  useHeroScheme,
} from '@/features/home/heroTheme';
import { radius, screenPadding, spacing } from '@/theme';
import { Gradient, KeyboardAvoider, PressableScale, Screen, Text } from '@/ui';

/**
 * The frame every auth screen sits in.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * Five screens, five layouts. Four centred their content and one did not, so
 * moving between them shifted the title for no reason a user could explain.
 * All five padded differently and each carried its own way back. One frame,
 * decided once.
 *
 * ---------------------------------------------------------------------------
 * THE BAND (2026-09-06)
 *
 * The auth screens used to be a large greeting and two fields on a blank
 * page, which read as unfinished next to Home. They now open the way Home
 * does: the same dusk photograph under the wordmark, the greeting set in
 * white on its lower edge, and the same curved bottom against the page. The
 * form sits under that on the page colour, so the fields have a surface to
 * belong to instead of floating.
 *
 * The band scrolls WITH the form rather than staying fixed. When the keyboard
 * opens on a small phone the fields have to move up, and a fixed band would
 * leave them nowhere to go.
 *
 * `band="compact"` is for the long forms (register, reset password): the
 * photograph is shortened so the first field is on screen before scrolling.
 *
 * ---------------------------------------------------------------------------
 * THE TITLE IS ON THE PHOTOGRAPH, NOT IN A HEADER BAR
 *
 * Auth screens open with a large greeting that is part of the page rather
 * than a nav bar label. Putting "Welcome back" in a 22pt header would make the
 * sign-in screen look like a settings sub-page. The back control, where a
 * screen has one, is the pale glass circle Home uses for its own controls on
 * the same photograph.
 */

export interface AuthShellProps {
  title: string;
  subtitle?: string;
  /** Back affordance. Off for the two entry points (login, register). */
  showBack?: boolean;
  /** Where back goes with no history — a deep link into a reset flow. */
  backTo?: string;
  /** Photograph height. `compact` for forms tall enough to scroll. */
  band?: 'tall' | 'compact';
  /** Sits below the form: sign-up prompts, "forgot password", legal notes. */
  footer?: React.ReactNode;
  children: React.ReactNode;
}

/** The wordmark asset is 308×82. */
const LOGO_WIDTH = 132;
const LOGO_HEIGHT = Math.round((LOGO_WIDTH * 82) / 308);

/** `#RRGGBB` with an alpha, for the gradient that settles the photo. */
function withAlpha(hex: string, alpha: number): string {
  const value = hex.replace('#', '');
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export function AuthShell({
  title,
  subtitle,
  showBack = false,
  backTo = '/(auth)/login',
  band = 'tall',
  footer,
  children,
}: AuthShellProps) {
  const insets = useSafeAreaInsets();
  const { width, height } = useWindowDimensions();
  const hero = useHeroScheme();

  const bandHeight = band === 'tall' ? Math.max(260, Math.round(height * 0.36)) : 212;

  const goBack = () => {
    if (router.canGoBack()) router.back();
    else router.replace(backTo as never);
  };

  return (
    <Screen unsafe>
      {/* The band is a photograph in both schemes, so the status bar is
          light here whatever the theme, as on Home. */}
      <StatusBar style="light" />

      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{ flexGrow: 1, paddingBottom: insets.bottom + spacing['2xl'] }}
          keyboardShouldPersistTaps="handled"
          bounces={false}
          showsVerticalScrollIndicator={false}
        >
          <View
            style={{
              minHeight: bandHeight,
              backgroundColor: hero.slab,
              overflow: 'hidden',
              borderBottomLeftRadius: radius.xl,
              borderBottomRightRadius: radius.xl,
              paddingTop: insets.top + spacing.md,
              paddingBottom: spacing.xl,
              paddingHorizontal: screenPadding,
              justifyContent: 'space-between',
            }}
          >
            <ExpoImage
              source={hero.image}
              style={{ position: 'absolute', top: 0, left: 0, width, height: (width * 1024) / 1536 }}
              contentFit="cover"
              cachePolicy="memory"
            />
            {/* Settles the lower half so the greeting sits on one reliable
                ground whatever the band's height crops the photo to. */}
            <Gradient
              colors={[withAlpha(hero.slab, 0), withAlpha(hero.slab, 0.55), hero.slab]}
              locations={[0.2, 0.62, 1]}
              style={StyleSheet.absoluteFillObject}
            />

            <View style={{ flexDirection: 'row', alignItems: 'center', gap: spacing.md }}>
              {showBack ? (
                <PressableScale
                  accessibilityRole="button"
                  accessibilityLabel="Back"
                  onPress={goBack}
                  activeScale={0.94}
                  style={styles.back}
                >
                  <Ionicons name="chevron-back" size={22} color={HERO_HEADER_INK} />
                </PressableScale>
              ) : null}
              <ExpoImage
                source={require('../../../assets/home/brand/logo.png')}
                style={{ width: LOGO_WIDTH, height: LOGO_HEIGHT }}
                contentFit="contain"
                contentPosition="left"
                accessibilityLabel="DealDirect"
                cachePolicy="memory"
              />
            </View>

            <View style={{ marginTop: spacing['2xl'] }}>
              <Text
                variant="display"
                accessibilityRole="header"
                style={{ color: HERO_TEXT, fontWeight: '700' }}
              >
                {title}
              </Text>
              {subtitle ? (
                <Text
                  variant="callout"
                  style={{ color: HERO_TEXT_MUTED, marginTop: spacing.xs, maxWidth: 340 }}
                >
                  {subtitle}
                </Text>
              ) : null}
            </View>
          </View>

          <View style={{ paddingHorizontal: screenPadding, paddingTop: spacing.xl }}>
            {children}

            {footer ? <View className="mt-xl">{footer}</View> : null}
          </View>
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}

const styles = StyleSheet.create({
  back: {
    width: 40,
    height: 40,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: HERO_HEADER_GLASS,
  },
});
