import Ionicons from '@expo/vector-icons/Ionicons';
import { useState } from 'react';
import { Dimensions, StyleSheet, View } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { gesture, radius, screenPadding, spacing, useTheme, withAlpha } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import { HomeSearchField } from './HomeSearchField';

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
 * THE SEARCH FIELD IS PINNED, NOT REVEALED — rebuilt 2026-08-24
 *
 * The first version slid a search row down out of the bar once the hero had
 * scrolled far enough. Reported as "this button appears from top to bottom",
 * and the objection is right: a control that arrives from somewhere is a
 * SECOND field, and the user had just watched the hero's own field leave.
 *
 * What happens now is a handover, engineered so it cannot be seen. The hero's
 * field scrolls up until its top edge reaches this bar's bottom edge; at that
 * exact offset this copy takes over, at the identical position and size, and
 * the content keeps scrolling underneath it. The field appears to STOP rather
 * than to reappear.
 *
 * Three things have to hold for the handover to be invisible, and all three are
 * load-bearing rather than styling:
 *
 *  1. **Identical geometry.** Both copies are the same component at the same
 *     52pt height inside the same `screenPadding`, so at the crossover they
 *     occupy the same pixels. This is why the header renders `HomeSearchField`
 *     rather than a lookalike.
 *  2. **An exact pin offset.** `pinOffset` is measured from the hero's real
 *     field position, not derived from the hero's height. The hero grows with
 *     text size and with the selected city's name, so a computed guess would
 *     hand over early on one device and late on another.
 *  3. **The two reds are the same red.** The block behind this field can snap
 *     to full height the instant the pin is crossed, because the hero directly
 *     behind it is the same brand fill. There is nothing to fade in but the
 *     field itself.
 *
 * The hero side counter-translates its own copy across the same short window,
 * so neither drifts while they cross over. See `HomeHero`.
 *
 * ---------------------------------------------------------------------------
 * ANIMATING HEIGHT HERE IS SAFE, AND THAT IS NOT GENERALLY TRUE
 *
 * This is ONE element with no siblings competing for the same axis, inside an
 * absolutely positioned parent that cannot reflow anything on the screen.
 * Nothing can be pushed by it, so nothing can collide with it — the condition
 * the tab dock's collision bug violated.
 *
 * Driven by the same scroll offset the reveal system already runs on the UI
 * thread. No second listener, and nothing re-rendered while scrolling.
 */

export interface HomeHeaderProps {
  /** Live scroll offset, from the reveal host. */
  scrollY: SharedValue<number>;
  /**
   * Scroll offset at which the hero's search field reaches this bar, measured
   * by the hero. 0 while unmeasured, which keeps this copy hidden.
   */
  pinOffset: number;
  name?: string;
  avatarUri?: string;
  hasUnread: boolean;
  city: City | null;
  /** Shared with the hero's copy — they are one field. See `HomeSearchField`. */
  searchValue: string;
  onSearchValueChange: (value: string) => void;
  onSubmitSearch: (term: string) => void;
  onOpenProperty: (id: string) => void;
  onOpenProfile: () => void;
  onOpenUpdates: () => void;
  onListProperty: () => void;
}

/**
 * The always-visible row. Exported so the hero can pad itself clear of it
 * rather than both guessing the same number.
 */
export const HOME_HEADER_ROW = 52;

/** The pill's height, matched exactly by the hero's copy. */
const SEARCH_FIELD = 52;

/** The pill plus the breathing room under it, once pinned. */
const SEARCH_ROW = SEARCH_FIELD + spacing.sm;

/**
 * How much scroll the crossover takes, shared with the hero so both sides run
 * on the same window. Short on purpose: it is a handover between two identical
 * things, not a transition, and every extra point is a point where two copies
 * of the same field are on screen at once.
 */
export const SEARCH_PIN_WINDOW = 10;

/** Enough to hold the suggestion panel while the field is focused. */
const FOCUSED_HEIGHT = Dimensions.get('window').height;

export function HomeHeader({
  scrollY,
  pinOffset,
  name,
  avatarUri,
  hasUnread,
  city,
  searchValue,
  onSearchValueChange,
  onSubmitSearch,
  onOpenProperty,
  onOpenProfile,
  onOpenUpdates,
  onListProperty,
}: HomeHeaderProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  /**
   * Held open while the panel is up.
   *
   * The panel renders INSIDE this bar, so the bar has to be tall enough to
   * contain it. On Android a child drawn outside its parent's bounds does not
   * receive touches at all — `overflow: 'visible'` would produce a panel that
   * looks right and cannot be tapped — so the height is real rather than
   * spilled.
   */
  const [searchFocused, setSearchFocused] = useState(false);

  /*
    Nothing until the hero has reported where its field actually is. A guessed
    pin would hand over at the wrong pixel, which is the one failure this whole
    arrangement exists to avoid.
  */
  const armed = pinOffset > 0;

  const searchRowStyle = useAnimatedStyle(() => {
    if (searchFocused) return { height: FOCUSED_HEIGHT, opacity: 1 };
    if (!armed) return { height: 0, opacity: 0 };

    const progress = interpolate(
      scrollY.value,
      [pinOffset, pinOffset + SEARCH_PIN_WINDOW],
      [0, 1],
      Extrapolation.CLAMP
    );

    return {
      /*
        Full height the instant the pin is crossed, rather than growing with
        the fade.

        A growing box would clip the field it contains and reveal it top-down —
        the shutter this replaced. Snapping is invisible because the block is
        brand red and the hero directly behind it is the same brand red, so
        there is nothing to see arrive except the field, which crossfades.
      */
      height: progress > 0 ? SEARCH_ROW : 0,
      opacity: progress,
    };
  }, [pinOffset, armed, searchFocused]);

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
        The pinned copy of the hero's field. Same component, same geometry —
        see the handover note at the top of this file for why that is the
        requirement rather than a convenience.

        `overflow: 'hidden'` keeps it clipped to zero before the pin, which is
        also what stops the not-yet-pinned copy from taking taps meant for the
        hero underneath: a zero-height clipped box has no touch area. While
        focused the height is the full screen, so the panel inside is genuinely
        contained and tappable on Android.
      */}
      <Animated.View style={[styles.searchRow, searchRowStyle]}>
        <HomeSearchField
          city={city}
          value={searchValue}
          onChangeText={onSearchValueChange}
          onSubmit={onSubmitSearch}
          onOpenProperty={onOpenProperty}
          onFocusChange={setSearchFocused}
          // No top margin here: the field's top edge has to land exactly on
          // this bar's bottom edge, which is where the hero's copy arrives.
          flush
        />
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
    // No shadow. The header and the hero beneath it are the same brand red, so
    // a drop shadow here casts a dark band onto an identical-coloured surface
    // and reads as a seam — the exact mismatch it looks like it should prevent.
    // Once scrolled, the header floats over the near-black page where a black
    // shadow is invisible regardless, so it was never buying separation. The
    // colour boundary against the content carries the header on its own.
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
    // Matches the hero's own horizontal inset, so the pill's left and right
    // edges land on the same pixels its hero copy occupied.
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
