import {
  CreditCard,
  Home,
  LineChart,
  MessageCircle,
  Trophy,
  User,
  type LucideIcon,
} from 'lucide-react-native';
import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import Animated, {
  interpolate,
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { radius, spacing, touchTarget, useTheme } from '@/theme';
import { Text } from './Text';

/**
 * A floating bottom navigation pill.
 *
 * A React Native port of a web component built with framer-motion, Tailwind and
 * lucide-react. None of those run here, so every part of it is rebuilt on the
 * native equivalents — `Pressable` for `<button>`, Reanimated for
 * framer-motion, `lucide-react-native` for the icons, and style objects for the
 * utility classes. What is preserved exactly is the MOTION, because that is
 * what the component is for.
 *
 * ---------------------------------------------------------------------------
 * THIS IS NOT THE APP'S NAVIGATION BAR
 *
 * `ui/TabBar.tsx` is. That one is wired to React Navigation, carries the four
 * real destinations plus the Post action, and takes its selected index from
 * navigation state so it survives back gestures and deep links.
 *
 * This is a standalone, self-contained primitive with the six items the
 * reference defines, holding its own selection. Rendering it as the app's tab
 * bar would produce a bar whose highlight and whose actual screen disagree the
 * moment anything navigates without a tap.
 *
 * ---------------------------------------------------------------------------
 * THE MOTION, AND WHY IT IS SPLIT ACROSS THREE CURVES
 *
 * The reference never animates two different KINDS of property on one curve,
 * and that is the whole reason it feels smooth:
 *
 *   shape   spring    width (350/32) and the entrance scale (300/26). Mass and
 *                     settle — this is the movement you actually watch.
 *   ink     190ms     opacity and the label's left margin. Fast and linear, so
 *                     the text is fully painted long before the shape stops
 *                     moving. A spring here reads as a flicker.
 *   colour  200ms     the selected pill and the icon. A spring on a colour
 *                     overshoots, which is either a flash of a saturation the
 *                     palette does not contain or a visible wobble.
 *
 * The entrance is the one deliberate exception: opacity and scale share a
 * single spring there, because an entrance is one object arriving and its fade
 * and its growth should land together.
 */

export interface BottomNavItem {
  label: string;
  icon: LucideIcon;
}

/** The six the reference defines. */
export const BOTTOM_NAV_ITEMS: readonly BottomNavItem[] = [
  { label: 'Home', icon: Home },
  { label: 'Portfolio', icon: LineChart },
  { label: 'Transactions', icon: CreditCard },
  { label: 'Messages', icon: MessageCircle },
  { label: 'Rewards', icon: Trophy },
  { label: 'Profile', icon: User },
];

/**
 * The expanded label's width, fixed rather than measured.
 *
 * This is the reference's `MOBILE_LABEL_WIDTH`, and keeping it fixed is what
 * lets the width animate at all without a measuring pass — an animated width
 * needs a number to travel to. The label is single-line and ellipsises into it.
 */
const LABEL_WIDTH = 72;

const DOCK_HEIGHT = 52;
const ITEM_HEIGHT = 40;
const ICON_SIZE = 22;
const ICON_STROKE = 2;

/** `min-w-[320px] max-w-[95vw]` in the reference. */
const MIN_DOCK_WIDTH = 320;

const SPRING_ENTRANCE = { stiffness: 300, damping: 26 } as const;
const SPRING_WIDTH = { stiffness: 350, damping: 32 } as const;
const INK_MS = 190;
const COLOR_MS = 200;

export interface BottomNavBarProps {
  style?: StyleProp<ViewStyle>;
  defaultIndex?: number;
  /** Pins the bar to the bottom of the screen, floating over content. */
  stickyBottom?: boolean;
  onItemPress?: (index: number, label: string) => void;
  /** Override the six defaults. */
  items?: readonly BottomNavItem[];
}

export function BottomNavBar({
  style,
  defaultIndex = 0,
  stickyBottom = false,
  onItemPress,
  items = BOTTOM_NAV_ITEMS,
}: BottomNavBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();
  const [activeIndex, setActiveIndex] = useState(defaultIndex);

  const entrance = useSharedValue(reduceMotion ? 1 : 0);

  // Driven from an effect, not from render. Assigning a shared value during
  // render happens before the node is mounted and is not something Reanimated
  // guarantees; an effect runs after commit, which is when there is something
  // on screen to animate.
  useEffect(() => {
    entrance.value = reduceMotion ? 1 : withSpring(1, SPRING_ENTRANCE);
  }, [entrance, reduceMotion]);

  const entranceStyle = useAnimatedStyle(() => ({
    opacity: entrance.value,
    transform: [{ scale: interpolate(entrance.value, [0, 1], [0.9, 1]) }],
  }));

  const handlePress = (index: number, label: string) => {
    setActiveIndex(index);
    onItemPress?.(index, label);
  };

  return (
    <View
      // `pointerEvents="box-none"` so the padded area around a sticky bar does
      // not swallow taps meant for the content scrolling underneath it.
      pointerEvents="box-none"
      style={[
        styles.outer,
        stickyBottom && {
          position: 'absolute',
          left: 0,
          right: 0,
          // `bottom-4`, plus the home indicator where there is one.
          bottom: insets.bottom > 0 ? insets.bottom : spacing.base,
        },
      ]}
    >
      <Animated.View
        accessibilityRole="tablist"
        accessibilityLabel="Bottom Navigation"
        style={[
          styles.dock,
          {
            backgroundColor: theme.colors.surface,
            borderColor: theme.colors.border,
            shadowColor: '#000',
          },
          entranceStyle,
          style,
        ]}
      >
        {items.map((item, index) => (
          <NavItem
            key={item.label}
            item={item}
            active={index === activeIndex}
            reduceMotion={reduceMotion}
            onPress={() => handlePress(index, item.label)}
          />
        ))}
      </Animated.View>
    </View>
  );
}

function NavItem({
  item,
  active,
  reduceMotion,
  onPress,
}: {
  item: BottomNavItem;
  active: boolean;
  reduceMotion: boolean;
  onPress: () => void;
}) {
  const theme = useTheme();
  const Icon = item.icon;
  const pressed = useSharedValue(0);

  /**
   * Three progresses, one per curve, all driven by the same `active` flag.
   *
   * Retargeted from an effect rather than derived inside a `useDerivedValue`.
   * Both work, but the effect states the lifecycle plainly — a state change
   * sets a new target and the spring or the timing takes it from wherever it
   * currently is, which is exactly what makes an interrupted transition
   * continuous instead of restarting.
   */
  const shape = useSharedValue(active ? 1 : 0);
  const ink = useSharedValue(active ? 1 : 0);
  const colour = useSharedValue(active ? 1 : 0);

  useEffect(() => {
    const to = active ? 1 : 0;
    if (reduceMotion) {
      shape.value = to;
      ink.value = to;
      colour.value = to;
      return;
    }
    shape.value = withSpring(to, SPRING_WIDTH);
    ink.value = withTiming(to, { duration: INK_MS });
    colour.value = withTiming(to, { duration: COLOR_MS });
  }, [active, reduceMotion, shape, ink, colour]);

  // `whileTap={{ scale: 0.97 }}`. A spring, not a curve: a press can be
  // released mid-flight, and a spring simply takes a new target instead of
  // having to finish or snap.
  const pressStyle = useAnimatedStyle(() => ({
    transform: [{ scale: 1 - pressed.value * 0.03 }],
  }));

  /**
   * Opacity on a correctly-coloured layer, NOT an interpolation from
   * `'transparent'`.
   *
   * `'transparent'` is rgba(0, 0, 0, 0) — black at zero alpha — so
   * interpolating it towards an opaque tint passes through semi-transparent
   * slate and the pill flashes dirty grey mid-transition. Fading a solid layer
   * blends against whatever is actually behind it, which is what the CSS this
   * was ported from does.
   */
  const pillStyle = useAnimatedStyle(() => ({ opacity: colour.value }));

  /**
   * `width` springs while `marginLeft` and `opacity` tween, exactly as the
   * reference splits them. `overflow: 'hidden'` is what turns the width change
   * into a reveal rather than a squash.
   */
  const labelStyle = useAnimatedStyle(() => ({
    width: interpolate(shape.value, [0, 1], [0, LABEL_WIDTH]),
    marginLeft: interpolate(ink.value, [0, 1], [0, spacing.sm]),
    opacity: ink.value,
  }));

  // Two icons stacked and crossfaded, rather than one icon whose colour
  // animates. lucide takes its colour as a prop on an SVG path, which is not a
  // style and so is not directly animatable; crossfading two copies produces
  // the same 200ms colour transition with no bridge work.
  const iconMuted = useAnimatedStyle(() => ({ opacity: 1 - colour.value }));
  const iconActive = useAnimatedStyle(() => ({ opacity: colour.value }));

  return (
    <Animated.View style={pressStyle}>
      <Pressable
        accessibilityRole="tab"
        accessibilityLabel={item.label}
        accessibilityState={{ selected: active }}
        onPressIn={() => {
          pressed.value = reduceMotion ? 0 : withSpring(1, SPRING_WIDTH);
        }}
        onPressOut={() => {
          pressed.value = withSpring(0, SPRING_WIDTH);
        }}
        onPress={onPress}
        style={styles.item}
      >
        <Animated.View
          style={[
            StyleSheet.absoluteFill,
            styles.pill,
            { backgroundColor: theme.colors.accentMuted },
            pillStyle,
          ]}
        />

        <View style={styles.icon}>
          <Animated.View style={[StyleSheet.absoluteFill, iconMuted]}>
            <Icon size={ICON_SIZE} strokeWidth={ICON_STROKE} color={theme.colors.textSecondary} />
          </Animated.View>
          <Animated.View style={[StyleSheet.absoluteFill, iconActive]}>
            <Icon size={ICON_SIZE} strokeWidth={ICON_STROKE} color={theme.colors.accent} />
          </Animated.View>
        </View>

        <Animated.View style={[styles.label, labelStyle]}>
          <Text
            variant="caption"
            numberOfLines={1}
            style={{
              // Pinned, so the text does not reflow as the clip narrows. A
              // `Text` inside an animating container is re-measured every frame
              // and would ellipsise progressively — the word arriving one
              // character at a time instead of being revealed. This is the
              // React Native stand-in for `whitespace-nowrap`.
              width: LABEL_WIDTH,
              color: theme.colors.accent,
              fontWeight: '500',
            }}
          >
            {item.label}
          </Text>
        </Animated.View>
      </Pressable>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  outer: {
    paddingHorizontal: spacing.base,
    alignItems: 'center',
  },
  dock: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'center',
    height: DOCK_HEIGHT,
    minWidth: MIN_DOCK_WIDTH,
    maxWidth: '100%',
    // `p-2` and `space-x-1`.
    paddingHorizontal: spacing.sm,
    gap: spacing.xs,
    borderRadius: radius.full,
    borderWidth: 1,
    // `shadow-xl`.
    shadowOpacity: 0.14,
    shadowRadius: 20,
    shadowOffset: { width: 0, height: 8 },
    elevation: 12,
  },
  item: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    height: ITEM_HEIGHT,
    minWidth: touchTarget.min,
    paddingHorizontal: spacing.md,
    borderRadius: radius.full,
  },
  pill: {
    borderRadius: radius.full,
  },
  icon: {
    width: ICON_SIZE,
    height: ICON_SIZE,
  },
  label: {
    overflow: 'hidden',
    justifyContent: 'center',
  },
});

export default BottomNavBar;
