import Ionicons from '@expo/vector-icons/Ionicons';
import { StatusBar } from 'expo-status-bar';
import { useCallback, useState } from 'react';
import { Pressable, StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  runOnJS,
  useAnimatedReaction,
  useAnimatedStyle,
  useDerivedValue,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { useTheme } from '@/theme';
import { Text } from '@/ui';
import { heroHeight } from './DetailHero';

/**
 * The detail screen's navigation bar.
 *
 * One bar, two appearances, and the same controls throughout. Over the photo it
 * is invisible chrome: dark translucent discs holding white glyphs, which is
 * the only treatment legible over an arbitrary user-uploaded photograph. Once
 * the photo has scrolled past it becomes an ordinary opaque nav bar carrying
 * the listing's title, so a user four sections deep still knows what they are
 * reading and still has a way out.
 *
 * The two appearances are cross-faded, not swapped. Every element that exists
 * in both — the glyphs — is drawn twice and its opacity interpolated against
 * scroll position, so the transition is continuous and reversible at any point
 * in the gesture rather than flipping at a threshold.
 *
 * ---------------------------------------------------------------------------
 * OPAQUE, NOT BLURRED
 *
 * iOS would put a material here and let content scroll under it. `expo-blur` is
 * a native module, and this project deliberately keeps those out of the render
 * path — see the note in `ui/Gradient.tsx` for what adding one costs the team.
 * So the collapsed bar is the SURFACE colour at full opacity, which is what iOS
 * itself falls back to under Reduce Transparency, and is honest: a translucent
 * fill with no blur behind it is a smear, not a material.
 *
 * If a dev-client rebuild is on the table anyway, this is the one place in the
 * app where a `BlurView` would earn its dependency. Swap the background view;
 * nothing else here changes.
 *
 * ---------------------------------------------------------------------------
 * THE STATUS BAR
 *
 * White glyphs over a photograph need light status-bar content; dark text on
 * the collapsed white bar needs the opposite. That is a discrete flip, not a
 * continuous one, so it crosses to JS through a single `useAnimatedReaction`
 * that fires only when the boolean actually changes — a `useAnimatedStyle`
 * cannot set it, and mapping it off every scroll frame would post a bridge
 * message per frame to set a value that is nearly always the same.
 */

export const HEADER_BAR_HEIGHT = 44;

/** Where the fade starts, measured from the point the photo's bottom lands. */
const FADE_TRAVEL = 72;

/**
 * 0 while the bar is over the photo, 1 once it is opaque.
 *
 * Exported because the section nav has to appear in step with the bar going
 * solid, and a second copy of this interpolation would be two constants that
 * silently drift apart — the strip would slide out from under a bar that had
 * not finished arriving, or after it had.
 *
 * The collapse point is measured WITHOUT parallax on purpose. Parallax holds
 * the photo behind the bar for longer, and reduced motion turns parallax off
 * entirely; taking the later of the two points would leave a user on that
 * setting with white glyphs over white content. Taking the earlier one only
 * means the bar goes solid while photography is still behind it, which is what
 * a nav bar ordinarily does.
 */
export function useHeaderProgress(scrollY: SharedValue<number>, insetTop: number) {
  // The hero is a share of the screen width now, not a constant, so the point
  // it stops covering the bar is per-device too.
  const { width } = useWindowDimensions();
  const collapsePoint = heroHeight(width) - (insetTop + HEADER_BAR_HEIGHT);

  return useDerivedValue(() =>
    interpolate(
      scrollY.value,
      [collapsePoint - FADE_TRAVEL, collapsePoint],
      [0, 1],
      Extrapolation.CLAMP
    )
  );
}

export interface DetailHeaderProps {
  /** Shown only once the bar is opaque, so it never sits over the photo. */
  title: string;
  scrollY: SharedValue<number>;
  onBack: () => void;
  onShare: () => void;
}

export function DetailHeader({ title, scrollY, onBack, onShare }: DetailHeaderProps) {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const [collapsed, setCollapsed] = useState(false);

  const barHeight = insets.top + HEADER_BAR_HEIGHT;
  const progress = useHeaderProgress(scrollY, insets.top);

  const setCollapsedFromUI = useCallback((next: boolean) => setCollapsed(next), []);

  useAnimatedReaction(
    () => progress.value > 0.5,
    (isCollapsed, previous) => {
      if (previous !== null && isCollapsed !== previous) {
        runOnJS(setCollapsedFromUI)(isCollapsed);
      }
    },
    [setCollapsedFromUI]
  );

  const backgroundStyle = useAnimatedStyle(() => ({ opacity: progress.value }));

  const titleStyle = useAnimatedStyle(() => ({
    opacity: interpolate(progress.value, [0.6, 1], [0, 1], Extrapolation.CLAMP),
    transform: [{ translateY: interpolate(progress.value, [0.6, 1], [6, 0], Extrapolation.CLAMP) }],
  }));

  return (
    <>
      {/* Collapsed, the bar sits on the page background, so the glyphs follow
          the app's scheme — the RESOLVED one, not `auto`, which reads the OS
          and would paint black glyphs on a black header for anyone who forced
          Dark on a Light phone. Expanded, it sits on the hero photograph and is
          forced light regardless. */}
      <StatusBar style={collapsed ? (theme.scheme === 'dark' ? 'light' : 'dark') : 'light'} />

      <View
        style={{ height: barHeight, paddingTop: insets.top }}
        className="absolute left-0 right-0 top-0 z-10"
      >
        <Animated.View
          pointerEvents="none"
          style={[
            StyleSheet.absoluteFillObject,
            { borderBottomWidth: StyleSheet.hairlineWidth, borderColor: theme.colors.border },
            backgroundStyle,
          ]}
          className="bg-surface"
        />

        <View
          className="flex-row items-center px-md"
          style={{ height: HEADER_BAR_HEIGHT }}
        >
          <HeaderControl
            icon="chevron-back"
            label="Go back"
            onPress={onBack}
            progress={progress}
          />

          {/*
            Centre-weighted rather than centred absolutely: with one control on
            each side the flexible middle IS the centre, and a long title
            truncates symmetrically instead of running under a control.
          */}
          <Animated.View style={titleStyle} className="flex-1 px-sm">
            <Text variant="bodyEmphasis" numberOfLines={1} className="text-center">
              {title}
            </Text>
          </Animated.View>

          <HeaderControl
            icon="share-outline"
            label="Share listing"
            onPress={onShare}
            progress={progress}
          />
        </View>
      </View>
    </>
  );
}

/**
 * A nav-bar control that survives both backgrounds.
 *
 * The dark disc fades out as the bar fades in, and the glyph is two stacked
 * copies cross-fading between white and the primary label colour. Animating the
 * `color` prop directly is not available to an icon font, and a mid-grey that
 * "works on both" works on neither.
 *
 * The disc paints at 36pt inside a 44pt target. Shrinking the target to match
 * the visible circle is the most common way a nav control ends up feeling
 * unreliable under the thumb.
 */
function HeaderControl({
  icon,
  label,
  onPress,
  progress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
  progress: SharedValue<number>;
}) {
  const theme = useTheme();

  const discStyle = useAnimatedStyle(() => ({ opacity: 1 - progress.value }));
  const overStyle = useAnimatedStyle(() => ({ opacity: 1 - progress.value }));
  const onBarStyle = useAnimatedStyle(() => ({ opacity: progress.value }));

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      hitSlop={8}
      className="h-11 w-11 items-center justify-center"
    >
      <Animated.View
        style={discStyle}
        className="h-9 w-9 items-center justify-center rounded-full bg-black/45"
      />
      <Animated.View style={[StyleSheet.absoluteFillObject, overStyle]} className="items-center justify-center">
        <Ionicons name={icon} size={22} color="#ffffff" />
      </Animated.View>
      <Animated.View style={[StyleSheet.absoluteFillObject, onBarStyle]} className="items-center justify-center">
        <Ionicons name={icon} size={22} color={theme.colors.textPrimary} />
      </Animated.View>
    </Pressable>
  );
}
