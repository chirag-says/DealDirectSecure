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

import { radius, spacing, touchTarget, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * The bottom dock.
 *
 * ---------------------------------------------------------------------------
 * A FLOATING PILL, NOT AN EDGE-TO-EDGE BAR — rebuilt 2026-08-14
 *
 * The previous bar spanned the full width, sat on a hairline border, and drew
 * four icons with four labels and a 2pt rule under the active one. Everything
 * about it was legible and none of it was memorable: it read as chrome the app
 * was obliged to have rather than as part of the product.
 *
 * This detaches from the screen edges and floats. Two things follow from that
 * and both are the point: the content scrolls visibly beneath it, so the app
 * feels layered rather than boxed; and the dock becomes an object with a
 * shape, which is what lets it carry a shadow and read as premium rather than
 * as a divider with icons on it.
 *
 * ---------------------------------------------------------------------------
 * THE ACTIVE TAB EXPANDS; THE OTHERS ARE ICON-ONLY
 *
 * Four labels shown permanently is four pieces of text competing at 11pt, and
 * on a 360pt screen "Properties" either truncates or forces every other label
 * to shrink with it. Showing the label only for the tab you are ON solves the
 * width problem and produces the strongest possible active state — the
 * selected tab is a different SHAPE, not just a different colour, which
 * survives both low contrast and colour blindness.
 *
 * The trade is real and worth naming: an inactive tab is an icon with no
 * caption. That is acceptable here and nowhere near universally — the four
 * glyphs are home, magnifier, heart and person, which are the four most
 * conventional icons in mobile software. It would NOT be acceptable for a
 * domain-specific icon, and a fifth destination should bring its label back
 * rather than push this pattern further.
 *
 * Every tab keeps its `accessibilityLabel` regardless, so a screen reader
 * always announces the destination whether or not it is painted.
 *
 * ---------------------------------------------------------------------------
 * POST IS AN ACTION IN A NAVIGATION BAR, DELIBERATELY
 *
 * The standing guidance is that a tab bar holds destinations only. This holds
 * one action, because posting a property is the single thing an owner opens
 * this app to do and burying it inside Profile would cost more than the rule
 * is worth. It is marked as an action rather than a destination by being the
 * only filled, circular, brand-coloured element here, and it never takes the
 * selected state.
 *
 * ---------------------------------------------------------------------------
 * THE ACTION IS RED; THE SELECTED TAB IS NOT — changed 2026-08-15
 *
 * That claim above — "the only brand-coloured element here" — stopped being
 * true when the selected tab was given a `brandMuted` pill and brand-red icon
 * and label. The dock then held two red objects side by side, one a
 * destination and one an action, and the reported symptom was that the post
 * button "competes with the navigation". It was not the button. It was that
 * nothing distinguished it.
 *
 * `colors.ts` already says which is which: brand is "the brand mark colour.
 * Not an action colour", accent is "the primary action colour". The selected
 * tab now takes the accent, and red means exactly one thing in this bar.
 *
 * The separator before the action is the second half. Four destinations, a
 * hairline, one action — the grouping is stated rather than inferred from the
 * fact that the last item happens to look different.
 */

/** Drawn in this order. A registered route absent from this map is skipped. */
const TABS: Record<string, { label: string; icon: keyof typeof Ionicons.glyphMap }> = {
  index: { label: 'Home', icon: 'home' },
  properties: { label: 'Properties', icon: 'search' },
  saved: { label: 'Saved', icon: 'heart' },
  profile: { label: 'Profile', icon: 'person' },
};

const DOCK_HEIGHT = 52;
const ITEM_HEIGHT = 40;
/** `size={22}` in the reference. */
const ICON_SIZE = 22;

/**
 * Ceiling on the expanded label, so "Properties" cannot push the pill past the
 * screen on a narrow device. The label is single-line and ellipsises into this.
 */
const LABEL_MAX_WIDTH = 72;

/**
 * MOTION — three separate decisions, and the separation is the point.
 *
 * Taken from a reference implementation whose dock felt notably smoother than
 * this one did, and the reason it felt that way is that it never animates two
 * different KINDS of property on the same curve:
 *
 *   shape   springs   — width, scale. Mass and settle; this is the thing you
 *                       watch, and a spring is what makes it feel physical.
 *   ink     tweens    — opacity, colour. Fast and linear. A spring on opacity
 *                       reads as a flicker, and a slow fade means you watch
 *                       half-transparent text slide across the screen.
 *
 * So: the pill's width springs while the label's opacity crossfades in about a
 * fifth of a second, and the label is fully painted well before the shape has
 * finished settling. The earlier version animated the width and then simply
 * MOUNTED the label at the end of it, which is what made it feel like a jump.
 */
const SPRING_SHAPE = { stiffness: 300, damping: 26 } as const;
/** Stiffer than the dock itself: a small element should settle faster. */
const SPRING_LABEL = { stiffness: 350, damping: 32 } as const;
const INK_MS = 190;
const COLOR_MS = 200;

/**
 * The dock settles in from 90%, rather than growing from nothing.
 *
 * Reanimated's stock `ZoomIn` starts at `scale: 0`, which on a 52pt pill is a
 * pop — it draws the eye to the chrome on every cold start. Ten percent is
 * enough to read as "arrived" and little enough to ignore.
 */
function dockEntering() {
  'worklet';
  return {
    initialValues: { opacity: 0, transform: [{ scale: 0.9 }] },
    animations: {
      // The reference puts ONE spring on the whole entrance, opacity included,
      // rather than splitting it the way the selection transition is split
      // below. That is right here and wrong there: an entrance is a single
      // object arriving, so its fade and its scale should share a curve and
      // finish together. Opacity overshoot clamps at 1 and is invisible.
      opacity: withSpring(1, SPRING_SHAPE),
      transform: [{ scale: withSpring(1, SPRING_SHAPE) }],
    },
  };
}

export interface TabBarProps extends BottomTabBarProps {
  onPost: () => void;
}

export function TabBar({ state, navigation, onPost }: TabBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  const visible = state.routes.filter((route) => TABS[route.name]);

  return (
    <View
      pointerEvents="box-none"
      style={{
        // ABSOLUTE, so the navigator reserves no strip for this.
        //
        // Laid out in flow, the dock occupied real height at the bottom of
        // every tab screen, and the band it sat in painted the navigator's own
        // background — a solid panel behind a pill that was supposed to be
        // floating. `tabBarClearance` has always documented the intention that
        // content scrolls UNDERNEATH the dock; this is what finally makes that
        // true, and it is why every tab screen pays that clearance.
        position: 'absolute',
        left: 0,
        right: 0,
        bottom: 0,
        paddingHorizontal: spacing.base,
        // Clears the home indicator when there is one, and still floats off
        // the bottom edge on a device without one.
        paddingBottom: insets.bottom > 0 ? insets.bottom : spacing.base,
      }}
    >
      <Animated.View
        // Arrives with the app rather than being simply present, which is the
        // difference between chrome and an object. Spring, not a fade: the
        // dock is a physical thing in this design language.
        entering={reduceMotion ? undefined : dockEntering}
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          // Hugs its contents and centres, instead of spanning the width. A
          // full-bleed pill is a bar with rounded ends; this reads as an
          // object sitting on top of the page.
          alignSelf: 'center',
          maxWidth: '100%',
          height: DOCK_HEIGHT,
          // `p-2` and `space-x-1` from the reference. The items used to sit
          // flush against each other and against the pill's edge, so the
          // selected background touched its neighbours' targets — 4pt between
          // them is what separates the pills visually once one is filled.
          paddingHorizontal: spacing.sm,
          gap: spacing.xs,
          borderRadius: radius.full,
          backgroundColor: theme.colors.surface,
          // A hairline as well as a shadow. On a light page the shadow alone
          // is nearly invisible at the top edge of the pill, and the outline
          // is what keeps the shape crisp there.
          borderWidth: 1,
          borderColor: theme.colors.border,
          shadowColor: '#000',
          shadowOpacity: 0.14,
          shadowRadius: 20,
          shadowOffset: { width: 0, height: 8 },
          elevation: 12,
        }}
      >
        {visible.map((route) => {
          const spec = TABS[route.name];
          if (!spec) return null;

          return (
            <TabItem
              key={route.key}
              spec={spec}
              focused={state.routes[state.index]?.key === route.key}
              reduceMotion={reduceMotion}
              onPress={() => {
                // `navigate`, not a raw dispatch, so a repeat visit returns to
                // the existing screen instead of pushing a duplicate of it.
                //
                // Only ever called for a tab that is NOT already selected —
                // `TabItem` withholds the handler while focused. The earlier
                // comment here claimed a tap on the active tab popped its stack
                // to the root, which this dock has never actually done.
                navigation.navigate(route.name);
              }}
            />
          );
        })}

        {/* Destinations end here. */}
        <View
          style={{
            width: 1,
            alignSelf: 'stretch',
            marginLeft: spacing.xs,
            marginVertical: spacing.md,
            backgroundColor: theme.colors.border,
          }}
        />

        {/* The one action. Circular, filled, and now the only red thing in the
            dock — see the module doc. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Post a property"
          onPress={onPost}
          activeScale={0.9}
          style={{
            width: ITEM_HEIGHT,
            height: ITEM_HEIGHT,
            marginLeft: spacing.xs,
            borderRadius: radius.full,
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: theme.colors.brand,
            // Raised off the dock rather than sitting flush in it. A filled
            // disc with no depth on a white pill reads as a swatch; a small
            // shadow is what makes it read as a button on top of a surface.
            shadowColor: theme.colors.brand,
            shadowOpacity: 0.35,
            shadowRadius: 8,
            shadowOffset: { width: 0, height: 3 },
            elevation: 4,
          }}
        >
          <Ionicons name="add" size={24} color={theme.colors.textOnAccent} />
        </PressableScale>
      </Animated.View>
    </View>
  );
}

/**
 * The icon, crossfaded rather than swapped.
 *
 * The reference animates its icon with `transition-colors duration-200`: one
 * glyph, its colour easing from muted to primary. This dock cannot do only
 * that, because it ALSO swaps outline for filled — a redundant cue for the
 * selected tab that survives low contrast and colour blindness, and one worth
 * keeping (see the module doc).
 *
 * A swap is instant by nature, so pairing it with a 200ms colour fade would
 * produce the worst of both: the shape snaps while the colour is still moving.
 * Stacking the two glyphs and crossfading their opacity on the same progress
 * gets the reference's smoothness AND keeps the shape cue — the outline
 * dissolves into the filled version, colour and all, in one movement.
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
      {/*
        Each layer centres its own glyph. `absoluteFill` alone stretches the
        layer to the box and pins the glyph to its top-left, and an Ionicons
        glyph's line box is a little taller than its nominal size — so the two
        copies landed a pixel apart and the crossfade read as a twitch.
      */}
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
 * ---------------------------------------------------------------------------
 * ONE INTERACTION, ONE SET OF DRIVEN VALUES — rewritten 2026-08-22
 *
 * This previously ran three unrelated mechanisms for a single state change:
 * `LinearTransition` measured and sprang the pill's width, `FadeIn`/`FadeOut`
 * animated a label that React mounted and unmounted, and `withTiming` moved the
 * colour. Nothing coordinated them, and the resulting faults were real rather
 * than theoretical:
 *
 *   - The label did not EXIST until `focused` flipped, so the pill began
 *     resizing before there was anything to reveal, and the text then appeared
 *     on top of a shape that was still travelling.
 *   - Deselect faded out over 120ms while select faded in over 190ms, with an
 *     unmount in between, so a switch could show a window with NO label on
 *     either tab while both pills were mid-flight. That reads as a jump.
 *   - Under a fast triple-tap all of it — mount, unmount, two entering
 *     animations, a layout transition and three timings — raced, and the
 *     outcome depended on frame timing rather than on the code.
 *
 * Now `focused` drives three shared values and nothing else. The label is
 * always mounted and its width is animated directly, so the pill's size is a
 * CONSEQUENCE of the label's width rather than a separately measured animation
 * chasing it. Interrupting mid-flight just retargets the springs.
 *
 * The three curves are still distinct, because they animate different kinds of
 * property — see the module doc. Distinct curves from one state is what the
 * reference does too; distinct MECHANISMS was the bug.
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

  /**
   * The label's natural width, measured once from an off-layout copy.
   *
   * An animated width needs a concrete target, and the reference hard-codes 72
   * for every item. That works there because its bar is a fixed 320 wide; this
   * dock hugs its contents, so a fixed 72 would pad "Home" with about 37pt of
   * nothing and make the pill wider than the word inside it.
   *
   * Measuring happens once, on mount, and never during a transition — so it
   * does not reintroduce the measure-while-animating coupling this rewrite
   * removed. Capped, so a long translation cannot push the dock off-screen.
   */
  const [labelWidth, setLabelWidth] = useState(0);

  const shape = useSharedValue(focused ? 1 : 0);
  const ink = useSharedValue(focused ? 1 : 0);
  const colour = useSharedValue(focused ? 1 : 0);

  useEffect(() => {
    const to = focused ? 1 : 0;
    if (reduceMotion) {
      shape.value = to;
      ink.value = to;
      colour.value = to;
      return;
    }
    shape.value = withSpring(to, SPRING_LABEL);
    ink.value = withTiming(to, { duration: INK_MS });
    colour.value = withTiming(to, { duration: COLOR_MS });
  }, [focused, reduceMotion, shape, ink, colour]);

  /**
   * The selected pill, as a solid layer whose OPACITY animates.
   *
   * It used to interpolate `backgroundColor` from `'transparent'` to
   * `accentMuted`, and that is wrong in a way that only shows up in motion.
   * `'transparent'` is not "no colour" — it is rgba(0, 0, 0, 0), black with
   * zero alpha. Interpolating it towards an opaque light blue travels through
   * RGB, so every midpoint is a semi-transparent SLATE: the pill flashed dirty
   * grey on its way in and again on its way out.
   *
   * Animating opacity on a correctly-coloured layer blends against whatever is
   * actually behind it, which is what the CSS the reference relies on does.
   */
  const pillStyle = useAnimatedStyle(() => ({ opacity: colour.value }));

  /**
   * Width springs; margin and opacity tween. `overflow: 'hidden'` is what makes
   * a width change read as a reveal instead of a squash.
   */
  const labelStyle = useAnimatedStyle(
    () => ({
      width: labelWidth * shape.value,
      marginLeft: spacing.sm * ink.value,
      opacity: ink.value,
    }),
    [labelWidth]
  );

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={spec.label}
      accessibilityState={{ selected: focused }}
      activeScale={0.97}
      onPress={focused ? undefined : onPress}
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        height: ITEM_HEIGHT,
        // `min-w-[44px]` in the reference, and independently the value in
        // `touchTarget.min`. An inactive item is only as wide as its icon plus
        // padding, which lands near 44 by arithmetic rather than by intent —
        // stating it means a smaller icon can never quietly shrink the target
        // below the minimum.
        minWidth: touchTarget.min,
        // Constant, matching `px-3`. It used to jump between two values on
        // selection, which was a third uncoordinated change; all of the growth
        // now comes from the label's own width and margin.
        paddingHorizontal: spacing.md,
        borderRadius: radius.full,
      }}
    >
      <Animated.View
        style={[
          StyleSheet.absoluteFill,
          styles.pillFill,
          { backgroundColor: theme.colors.accentMuted },
          pillStyle,
        ]}
      />

      <TabIcon icon={spec.icon} progress={colour} />

      <Animated.View style={[styles.labelClip, labelStyle]}>
        <Text
          variant="footnote"
          numberOfLines={1}
          style={{
            /*
              PINNED to the measured width, and this is the fix for the label
              appearing to type itself out.

              A `Text` inside a container whose width is animating gets
              re-measured every frame, and with `numberOfLines={1}` it
              ellipsises to whatever space it currently has — so the word
              arrived one character at a time ("P…", "Pro…", "Prope…") instead
              of sliding out from behind the clip. The web has no such problem
              because `whitespace-nowrap` keeps the span at its natural width
              and lets `overflow: hidden` do the clipping. An explicit width is
              the React Native equivalent: the text stops reflowing, overflows
              the shrinking clip, and is revealed rather than rebuilt.
            */
            width: labelWidth || undefined,
            color: theme.colors.accent,
            fontWeight: '600',
          }}
        >
          {spec.label}
        </Text>
      </Animated.View>

      {/*
        The measuring copy. Absolutely positioned so it contributes nothing to
        layout, and hidden from accessibility so the label is not announced
        twice.
      */}
      <View
        style={styles.measure}
        pointerEvents="none"
        accessibilityElementsHidden
        importantForAccessibility="no-hide-descendants"
      >
        <Text
          variant="footnote"
          numberOfLines={1}
          // `flex-start`, or the text stretches to fill the measuring box and
          // every label reports the same width back.
          style={{ alignSelf: 'flex-start', fontWeight: '600' }}
          onLayout={(event) => {
            const measured = Math.ceil(event.nativeEvent.layout.width);
            if (measured > 0) setLabelWidth(measured);
          }}
        >
          {spec.label}
        </Text>
      </View>
    </PressableScale>
  );
}

const styles = StyleSheet.create({
  pillFill: {
    borderRadius: radius.full,
  },
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
  labelClip: {
    overflow: 'hidden',
    justifyContent: 'center',
    // Pins the text to the LEFT edge of the clip, so a narrowing container
    // reveals the word from its start. Centred, the clip would eat both ends
    // and the middle of the word would survive longest.
    alignItems: 'flex-start',
  },
  measure: {
    position: 'absolute',
    opacity: 0,
    left: 0,
    top: 0,
    /*
      A definite width, and it is load-bearing.

      An absolutely positioned child with only `left` set is laid out against
      whatever space remains in the parent — and the parent here is a collapsed
      pill about 45pt wide, so "Properties" would have been measured against 45
      and reported back truncated. Every label would then animate to a width
      narrower than the word it has to show.

      Giving the measurer exactly `LABEL_MAX_WIDTH` does both jobs at once: the
      text lays out unconstrained up to the cap, and anything longer is
      naturally clamped to it, which is the cap this dock wants anyway.
    */
    width: LABEL_MAX_WIDTH,
  },
});
