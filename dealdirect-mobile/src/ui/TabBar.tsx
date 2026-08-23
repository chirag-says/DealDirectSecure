import Ionicons from '@expo/vector-icons/Ionicons';
import type { BottomTabBarProps } from '@react-navigation/bottom-tabs';
import { useEffect, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { radius, touchTarget, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * The bottom bar.
 *
 * ---------------------------------------------------------------------------
 * AN EDGE-TO-EDGE BAR WITH PERMANENT LABELS — rebuilt 2026-08-24
 *
 * This was a floating pill whose ACTIVE tab expanded to reveal its label while
 * the others stayed icon-only. It looked good and it carried a defect that took
 * three attempts to kill: two tabs animating their own widths inside a
 * content-hugging row, with nothing constraining the sum, so a switch could
 * make the row wider than the screen. React Native children default to
 * `flexShrink: 0`, so they do not compress to fit — they overflow, and on a
 * rounded pill with no clipping they spill over each other. That was the
 * reported flicker.
 *
 * The fix that survived is to stop animating layout altogether. Every
 * destination now occupies an equal `flex: 1` share of the full width, its
 * label is permanently mounted and permanently visible, and NOTHING in this bar
 * changes width, ever. The collision is not mitigated; it is unrepresentable,
 * because there is no longer a quantity that could exceed a budget.
 *
 * What still animates is what cannot affect layout:
 *
 *   colour   timing 200ms   icon crossfade and label tint
 *   pill     timing 200ms   the selected chip's opacity
 *   indicator spring        one shared underline that slides between tabs
 *
 * The indicator is a single element, so two of them can never exist and the
 * old failure mode has no way back in. It moves on a transform, which does not
 * touch Yoga at all.
 *
 * ---------------------------------------------------------------------------
 * THE ACTION SITS IN THE MIDDLE
 *
 * Four destinations, two either side of a raised circular action. The standing
 * guidance is that a tab bar holds destinations only; this holds one action,
 * because listing a property is the thing the supply side of a marketplace
 * opens the app to do, and it is marked as an action rather than a destination
 * by being the only filled, circular, brand-coloured element here. It never
 * takes the selected state.
 *
 * Notifications are NOT a destination. They live as a bell in Home's hero,
 * which is where the portals this is modelled on put them, and it is what frees
 * the fifth slot for the action.
 *
 * ---------------------------------------------------------------------------
 * THE SELECTED TAB IS ACCENT, THE ACTION IS BRAND
 *
 * `colors.ts` says which is which: brand is "the brand mark colour. Not an
 * action colour", accent is "the primary action colour". Red means exactly one
 * thing in this bar, and it is the button in the middle.
 */

/**
 * Drawn in this order, split around the action. A registered route absent from
 * this map is skipped, which is what keeps the redirect-only routes
 * (`properties`, `saved`) and the dark `chat` route out of the bar without this
 * file knowing about them.
 */
const TABS: Record<string, { label: string; icon: keyof typeof Ionicons.glyphMap }> = {
  index: { label: 'Home', icon: 'home' },
  search: { label: 'Search', icon: 'search' },
  activity: { label: 'Activity', icon: 'heart' },
  profile: { label: 'Profile', icon: 'person' },
};

const BAR_HEIGHT = 58;
const ICON_SIZE = 23;
const ACTION_SIZE = 46;
/** Width of the sliding underline under the selected tab. */
const INDICATOR_WIDTH = 22;

const COLOR_MS = 200;
/** The indicator travels on a spring; it is the only springy thing left. */
const SPRING_INDICATOR = { stiffness: 350, damping: 32 } as const;

export interface TabBarProps extends BottomTabBarProps {
  /** Raised centre action. Not a destination; see the module doc. */
  onAction: () => void;
}

export function TabBar({ state, navigation, onAction }: TabBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  const visible = state.routes.filter((route) => TABS[route.name]);

  /**
   * `state.index` indexes `state.routes`, which includes the redirect-only and
   * dark routes this bar filters out, so it cannot be used directly. A focused
   * route that is not in the bar — the instant a `dealdirect://properties` link
   * lands on its redirect — gives -1, and the indicator holds its last position
   * through it rather than flying to the left edge for a frame.
   */
  const focusedKey = state.routes[state.index]?.key;
  const activeIndex = visible.findIndex((route) => route.key === focusedKey);

  /**
   * Where the underline sits, as a slot index.
   *
   * One shared value for the whole bar. The slot COUNT includes the action, so
   * the indicator's arithmetic matches the layout: destinations occupy slots
   * 0, 1, then 3, 4, with the action at 2.
   */
  const slotCount = visible.length + 1;
  const indicator = useSharedValue(slotIndexFor(activeIndex));

  useEffect(() => {
    if (activeIndex < 0) return;
    const slot = slotIndexFor(activeIndex);
    indicator.value = reduceMotion ? slot : withSpring(slot, SPRING_INDICATOR);
  }, [activeIndex, reduceMotion, indicator]);

  const [width, setWidth] = useState(0);
  const slotWidth = width > 0 ? width / slotCount : 0;

  const indicatorStyle = useAnimatedStyle(
    () => ({
      // A transform, not `left`. Layout is never touched, so the bar cannot
      // reflow while this moves.
      transform: [{ translateX: indicator.value * slotWidth + (slotWidth - INDICATOR_WIDTH) / 2 }],
      opacity: activeIndex < 0 || slotWidth === 0 ? 0 : 1,
    }),
    [slotWidth, activeIndex]
  );

  return (
    <View
      onLayout={(event) => setWidth(event.nativeEvent.layout.width)}
      style={{
        // ABSOLUTE, so the navigator reserves no strip for this and content
        // scrolls underneath. Every tab screen pays `tabBarClearance` for it.
        position: 'absolute',
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: theme.colors.surface,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: theme.colors.border,
        paddingBottom: insets.bottom,
      }}
    >
      {/* The sliding selection marker. One element for the whole bar, which is
          why two selected states cannot coexist. */}
      <Animated.View
        pointerEvents="none"
        style={[
          {
            position: 'absolute',
            top: 0,
            left: 0,
            width: INDICATOR_WIDTH,
            height: 3,
            borderRadius: radius.full,
            backgroundColor: theme.colors.accent,
          },
          indicatorStyle,
        ]}
      />

      <View style={{ flexDirection: 'row', alignItems: 'center', height: BAR_HEIGHT }}>
        {visible.slice(0, 2).map((route, index) => (
          <TabItem
            key={route.key}
            spec={TABS[route.name]!}
            focused={index === activeIndex}
            reduceMotion={reduceMotion}
            onPress={() => navigation.navigate(route.name)}
          />
        ))}

        <ActionButton onPress={onAction} />

        {visible.slice(2).map((route, index) => (
          <TabItem
            key={route.key}
            spec={TABS[route.name]!}
            focused={index + 2 === activeIndex}
            reduceMotion={reduceMotion}
            onPress={() => navigation.navigate(route.name)}
          />
        ))}
      </View>
    </View>
  );
}

/** Destinations 0 and 1 keep their slot; 2 and 3 shift right past the action. */
function slotIndexFor(activeIndex: number): number {
  if (activeIndex < 0) return 0;
  return activeIndex < 2 ? activeIndex : activeIndex + 1;
}

/**
 * The raised action.
 *
 * A circle that overlaps the bar's top edge, so it reads as sitting ON the bar
 * rather than in it — the standard signal that this is an action and not a
 * fifth place to go.
 */
function ActionButton({ onPress }: { onPress: () => void }) {
  const theme = useTheme();

  return (
    <View style={{ flex: 1, alignItems: 'center' }}>
      <PressableScale
        accessibilityRole="button"
        accessibilityLabel="List a property"
        onPress={onPress}
        activeScale={0.9}
        style={{
          width: ACTION_SIZE,
          height: ACTION_SIZE,
          marginTop: -ACTION_SIZE / 3,
          borderRadius: radius.full,
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: theme.colors.brand,
          shadowColor: theme.colors.brand,
          shadowOpacity: 0.35,
          shadowRadius: 8,
          shadowOffset: { width: 0, height: 3 },
          elevation: 6,
        }}
      >
        <Ionicons name="add" size={26} color={theme.colors.textOnAccent} />
      </PressableScale>
    </View>
  );
}

/**
 * The icon, crossfaded rather than swapped.
 *
 * The bar swaps outline for filled, which is a redundant cue for the selected
 * tab that survives low contrast and colour blindness. A swap is instant by
 * nature, so pairing it with a 200ms colour fade would produce the worst of
 * both: the shape snaps while the colour is still moving. Stacking the two
 * glyphs and crossfading their opacity on the same progress keeps the shape cue
 * and the smoothness — the outline dissolves into the filled version, colour
 * and all, in one movement.
 */
function TabIcon({
  icon,
  progress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  progress: SharedValue<number>;
}) {
  const theme = useTheme();

  const outline = useAnimatedStyle(() => ({ opacity: 1 - progress.value }));
  const filled = useAnimatedStyle(() => ({ opacity: progress.value }));

  return (
    <View style={styles.iconBox}>
      {/* Each layer centres its own glyph. `absoluteFill` alone stretches the
          layer to the box and pins the glyph to its top-left, and an Ionicons
          glyph's line box is a little taller than its nominal size — so the two
          copies landed a pixel apart and the crossfade read as a twitch. */}
      <Animated.View style={[styles.iconLayer, outline]}>
        <Ionicons
          name={`${icon}-outline` as keyof typeof Ionicons.glyphMap}
          size={ICON_SIZE}
          color={theme.colors.textSecondary}
        />
      </Animated.View>
      <Animated.View style={[styles.iconLayer, filled]}>
        <Ionicons name={icon} size={ICON_SIZE} color={theme.colors.accent} />
      </Animated.View>
    </View>
  );
}

/**
 * One destination.
 *
 * Fixed `flex: 1` share, permanently mounted and permanently visible label. It
 * owns no geometry at all — the only per-tab animated value is a colour, which
 * cannot affect layout — so no number of simultaneous transitions can make this
 * bar wider than the screen. That is the whole point of the rebuild; see the
 * module doc.
 */
function TabItem({
  spec,
  focused,
  reduceMotion,
  onPress,
}: {
  spec: { label: string; icon: keyof typeof Ionicons.glyphMap };
  focused: boolean;
  reduceMotion: boolean;
  onPress: () => void;
}) {
  const theme = useTheme();
  const colour = useSharedValue(focused ? 1 : 0);

  useEffect(() => {
    const to = focused ? 1 : 0;
    colour.value = reduceMotion ? to : withTiming(to, { duration: COLOR_MS });
  }, [focused, reduceMotion, colour]);

  const labelStyle = useAnimatedStyle(() => ({ opacity: 0.7 + colour.value * 0.3 }));

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={spec.label}
      accessibilityState={{ selected: focused }}
      activeScale={0.94}
      // Withheld while focused, so a repeat tap on the current tab does nothing
      // rather than re-navigating.
      onPress={focused ? undefined : onPress}
      style={{
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        height: BAR_HEIGHT,
        minWidth: touchTarget.min,
        gap: 3,
      }}
    >
      <TabIcon icon={spec.icon} progress={colour} />

      <Animated.View style={labelStyle}>
        <Text
          variant="caption"
          numberOfLines={1}
          style={{
            color: focused ? theme.colors.accent : theme.colors.textSecondary,
            fontWeight: focused ? '700' : '500',
          }}
        >
          {spec.label}
        </Text>
      </Animated.View>
    </PressableScale>
  );
}

const styles = StyleSheet.create({
  iconBox: {
    width: ICON_SIZE,
    height: ICON_SIZE,
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconLayer: {
    ...StyleSheet.absoluteFillObject,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
