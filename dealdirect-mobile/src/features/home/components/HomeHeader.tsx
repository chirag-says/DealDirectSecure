import Ionicons from '@expo/vector-icons/Ionicons';
import { StyleSheet, View } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  useReducedMotion,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { gesture, radius, screenPadding, spacing, useTheme, withAlpha } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';

/**
 * Home's header. Pinned, always visible, at every scroll position.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS ALWAYS THERE RATHER THAN FADING IN
 *
 * The first version of this appeared only once the hero had scrolled away,
 * which left the top of the screen with no controls at all for the first
 * screenful — exactly the gap it was built to close, just moved. Identity,
 * listing and notifications are not "things you reach for after scrolling";
 * they are the frame the screen lives in.
 *
 * So this row never moves. What CHANGES with scroll is one thing: the search
 * field joins it once the hero's own search field has left. Two search fields
 * on screen at once would be two places for the same query to live, and an
 * empty slot waiting for one would be a gap under a bar.
 *
 * That makes the header the only part of Home that is chrome. Everything
 * beneath it — headline, city, intent chips, the hero's search field — scrolls
 * away as content, which is what it is.
 *
 * ---------------------------------------------------------------------------
 * THE ONE ANIMATED HEIGHT IN THE APP, AND WHY IT IS SAFE HERE
 *
 * The search row's height animates from zero. Animating layout is normally the
 * thing to avoid — the tab dock's collision bug was exactly that — but the
 * conditions that made it dangerous are absent: this is ONE element, with no
 * siblings competing for the same axis, inside a fixed-width absolutely
 * positioned parent that cannot reflow anything else on the screen. Nothing
 * can be pushed by it, so nothing can collide with it.
 *
 * Driven by the same scroll offset the reveal system already runs on the UI
 * thread. No second listener, no state, nothing re-rendered while scrolling.
 */

export interface HomeHeaderProps {
  /** Live scroll offset, from the reveal host. */
  scrollY: SharedValue<number>;
  /** Measured hero height, so the search row appears as the hero's own leaves. */
  heroHeight: number;
  name?: string;
  avatarUri?: string;
  hasUnread: boolean;
  cityLabel?: string;
  onOpenProfile: () => void;
  onOpenUpdates: () => void;
  onSearch: () => void;
  onListProperty: () => void;
}

/**
 * The always-visible row. Exported so the hero can pad itself clear of it
 * rather than both guessing the same number.
 */
export const HOME_HEADER_ROW = 52;

/** The search row, once it has arrived. */
const SEARCH_ROW = 48;

export function HomeHeader({
  scrollY,
  heroHeight,
  name,
  avatarUri,
  hasUnread,
  cityLabel,
  onOpenProfile,
  onOpenUpdates,
  onSearch,
  onListProperty,
}: HomeHeaderProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  /*
    The search row arrives as the hero's own search field leaves the top of the
    screen. The hero is the first thing in the scroll view and its field sits
    at its bottom, so that moment is roughly the hero's height less the header
    already covering it.

    Measured rather than assumed: the hero grows with the user's text size and
    with the length of the selected city, so a constant would swap early on a
    large-text device and leave both fields on screen at once on a small one.
  */
  const end = Math.max(heroHeight - insets.top - HOME_HEADER_ROW - 8, 100);
  const start = Math.max(end - 56, 40);

  const searchRowStyle = useAnimatedStyle(() => {
    const progress = interpolate(scrollY.value, [start, end], [0, 1], Extrapolation.CLAMP);

    return {
      height: SEARCH_ROW * progress,
      opacity: progress,
    };
  }, [start, end]);

  const searchInnerStyle = useAnimatedStyle(() => {
    const progress = interpolate(scrollY.value, [start, end], [0, 1], Extrapolation.CLAMP);

    return {
      // A short rise, so the field reads as coming up out of the bar rather
      // than being revealed by a shutter. Skipped under reduced motion.
      transform: [{ translateY: reduceMotion ? 0 : interpolate(progress, [0, 1], [6, 0]) }],
    };
  }, [start, end, reduceMotion]);

  return (
    <View
      style={[
        styles.host,
        { paddingTop: insets.top, backgroundColor: theme.colors.brand },
      ]}
    >
      {/* Always. Identity, the selling action, notifications. */}
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
            <Ionicons name="person-circle-outline" size={30} color={theme.colors.textOnAccent} />
          )}
        </PressableScale>

        <View style={{ flex: 1 }} />

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="List your property"
          onPress={onListProperty}
          activeScale={0.96}
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            gap: 6,
            height: 34,
            paddingHorizontal: spacing.md,
            borderRadius: radius.full,
            backgroundColor: theme.colors.surface,
          }}
        >
          <Ionicons name="add" size={15} color={theme.colors.brand} />
          <Text variant="footnote" style={{ color: theme.colors.brand, fontWeight: '700' }}>
            List property
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
            <View style={[styles.dot, { backgroundColor: theme.colors.textOnAccent }]} />
          ) : null}
        </PressableScale>
      </View>

      {/*
        Arrives as the hero's own search field leaves.

        `overflow: 'hidden'` is what turns the height change into a reveal
        rather than a squash, and it is also what keeps the field from
        spilling out of the bar while the height is still travelling.
      */}
      <Animated.View style={[styles.searchRow, searchRowStyle]}>
        <Animated.View style={[styles.searchInner, searchInnerStyle]}>
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
            <Text variant="footnote" tone="secondary" numberOfLines={1} style={{ flex: 1 }}>
              {cityLabel ? `Search in ${cityLabel}` : 'Search locality or project'}
            </Text>
          </PressableScale>
        </Animated.View>
      </Animated.View>
    </View>
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
    shadowOpacity: 0.1,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 3 },
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    height: HOME_HEADER_ROW,
    paddingHorizontal: screenPadding,
  },
  searchRow: {
    overflow: 'hidden',
    justifyContent: 'center',
    paddingHorizontal: screenPadding,
  },
  searchInner: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingBottom: spacing.sm,
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
