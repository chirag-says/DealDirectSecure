import Ionicons from '@expo/vector-icons/Ionicons';
import { useState } from 'react';
import { StyleSheet, View } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  runOnJS,
  useAnimatedReaction,
  useAnimatedStyle,
  useReducedMotion,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { gesture, radius, screenPadding, spacing, useTheme, withAlpha } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';

/**
 * The hero, condensed, once the real one has scrolled away.
 *
 * ---------------------------------------------------------------------------
 * WHY HOME NEEDS THIS AND THE OTHER TABS DO NOT
 *
 * Search, Activity, Updates and Profile all put their controls in a
 * `ScreenHeader` that sits OUTSIDE the scrolling area, so they are already
 * pinned. Home is the exception: its hero is the first thing in the scroll
 * view, which means the search field, the city and the bell all leave the
 * screen the moment a user starts reading the rails — on a screen whose whole
 * job is to start a session.
 *
 * So the hero hands its two essential controls to this bar and the bar takes
 * over. Search stays reachable at every scroll position, which is the actual
 * requirement; everything else in the hero is a first-screen affordance and is
 * allowed to leave.
 *
 * ---------------------------------------------------------------------------
 * IT CROSS-FADES WITH THE HERO RATHER THAN SLIDING IN OVER IT
 *
 * Driven by the same scroll offset the reveal system already runs on the UI
 * thread — no second listener, no `useState`, nothing re-rendered while
 * scrolling. The bar is transparent to touches until it is actually visible,
 * because a full-width invisible header pinned over the top of the screen
 * would swallow the first tap on whatever is underneath it.
 *
 * The threshold is the hero's MEASURED height, passed in rather than guessed:
 * the hero grows with the user's text size and with the length of a city name,
 * and a hard-coded number would hand over early on a large-text device and
 * leave a gap on a small one.
 */

export interface HomeStickyHeaderProps {
  /** Live scroll offset, from the reveal host. */
  scrollY: SharedValue<number>;
  /** Measured hero height. The bar is fully in a little before this. */
  heroHeight: number;
  name?: string;
  avatarUri?: string;
  hasUnread: boolean;
  cityLabel?: string;
  onOpenProfile: () => void;
  onOpenUpdates: () => void;
  onSearch: () => void;
}

const BAR_HEIGHT = 56;

/**
 * How far before the hero fully leaves that the bar finishes arriving.
 *
 * The handover reads as one object condensing rather than two objects swapping
 * if the bar is solid slightly before the hero's search field is gone.
 */
const HANDOVER = 90;

export function HomeStickyHeader({
  scrollY,
  heroHeight,
  name,
  avatarUri,
  hasUnread,
  cityLabel,
  onOpenProfile,
  onOpenUpdates,
  onSearch,
}: HomeStickyHeaderProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  /*
    Falls back to a sane threshold before the hero has been measured. On the
    very first frame `heroHeight` is 0, and without this the bar would be fully
    opaque at the top of the screen, covering the hero it is supposed to
    replace.
  */
  const end = Math.max(heroHeight - HANDOVER, 120);
  const start = Math.max(end - 60, 40);

  const containerStyle = useAnimatedStyle(() => {
    const progress = interpolate(scrollY.value, [start, end], [0, 1], Extrapolation.CLAMP);

    return {
      opacity: progress,
      // A short drop, so the bar arrives from behind the status bar rather
      // than fading in on the spot. Skipped under reduced motion, where the
      // fade alone still communicates the change.
      transform: [{ translateY: reduceMotion ? 0 : interpolate(progress, [0, 1], [-8, 0]) }],
    };
  }, [start, end, reduceMotion]);

  /**
   * Whether the bar can be touched.
   *
   * This is the one thing that CANNOT ride on the animated style. An invisible
   * full-width bar pinned across the top would still swallow the first tap on
   * whatever is beneath it, and at scroll zero that is the hero's avatar, its
   * "List property" pill and its bell — the three controls most likely to be
   * pressed first.
   *
   * A reaction rather than a style: it flips a single boolean once per
   * crossing, not once per frame, so the cost is two re-renders for a whole
   * scroll down and back rather than sixty a second.
   */
  const [interactive, setInteractive] = useState(false);

  useAnimatedReaction(
    () => scrollY.value >= end,
    (isPast, wasPast) => {
      if (isPast !== wasPast) runOnJS(setInteractive)(isPast);
    },
    [end]
  );

  return (
    <Animated.View
      style={[
        styles.host,
        { paddingTop: insets.top, backgroundColor: theme.colors.brand },
        containerStyle,
      ]}
      pointerEvents={interactive ? 'auto' : 'none'}
    >
      <View style={styles.row}>
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Your account"
          hitSlop={gesture.hitSlop}
          onPress={onOpenProfile}
          activeScale={0.94}
        >
          {name ? (
            <Avatar uri={avatarUri} name={name} size="sm" />
          ) : (
            <Ionicons name="person-circle-outline" size={28} color={theme.colors.textOnAccent} />
          )}
        </PressableScale>

        {/* The one control that must never leave the screen. */}
        <PressableScale
          accessibilityRole="search"
          accessibilityLabel="Search properties"
          onPress={onSearch}
          activeScale={0.99}
          style={{
            flex: 1,
            flexDirection: 'row',
            alignItems: 'center',
            gap: spacing.sm,
            height: 38,
            paddingHorizontal: spacing.md,
            borderRadius: radius.full,
            backgroundColor: theme.colors.surface,
          }}
        >
          <Ionicons name="search" size={16} color={theme.colors.textSecondary} />
          <Text variant="footnote" tone="secondary" numberOfLines={1} className="flex-1">
            {cityLabel ? `Search in ${cityLabel}` : 'Search locality or project'}
          </Text>
        </PressableScale>

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={hasUnread ? 'Updates, you have unread items' : 'Updates'}
          hitSlop={gesture.hitSlop}
          onPress={onOpenUpdates}
          activeScale={0.94}
          style={{
            width: 34,
            height: 34,
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: radius.full,
            borderWidth: 1,
            borderColor: withAlpha(theme.colors.textOnAccent, 0.35),
          }}
        >
          <Ionicons name="notifications-outline" size={17} color={theme.colors.textOnAccent} />
          {hasUnread ? (
            <View
              style={[styles.dot, { backgroundColor: theme.colors.textOnAccent }]}
            />
          ) : null}
        </PressableScale>
      </View>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  host: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    // Above the scroll content, below any sheet or modal.
    zIndex: 10,
    elevation: 8,
    shadowColor: '#000',
    shadowOpacity: 0.12,
    shadowRadius: 12,
    shadowOffset: { width: 0, height: 4 },
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    height: BAR_HEIGHT,
    paddingHorizontal: screenPadding,
  },
  dot: {
    position: 'absolute',
    top: 6,
    right: 7,
    width: 7,
    height: 7,
    borderRadius: radius.full,
  },
});
