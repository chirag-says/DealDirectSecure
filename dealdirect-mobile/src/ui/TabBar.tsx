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
 * Five labels shown permanently is five pieces of text competing at 11pt, and
 * on a 360pt screen they either truncate or force each other to shrink.
 * Showing the label only for the tab you are ON solves the width problem and
 * produces the strongest possible active state — the selected tab is a
 * different SHAPE, not just a different colour, which survives both low
 * contrast and colour blindness.
 *
 * The trade is real and worth naming: an inactive tab is an icon with no
 * caption. That is acceptable here and nowhere near universally — the five
 * glyphs are house, magnifier, heart, bell and person, which are among the
 * most conventional icons in mobile software. It would NOT be acceptable for a
 * domain-specific icon.
 *
 * Five is the ceiling for this pattern, and it is now at it. A sixth
 * destination must not be added by shrinking the label; it would mean either
 * an edge-to-edge bar with permanent captions, or accepting that one of the
 * five does not deserve a slot. When the question comes up, the second answer
 * is usually the right one — see the note on the Post action below.
 *
 * Every tab keeps its `accessibilityLabel` regardless, so a screen reader
 * always announces the destination whether or not it is painted.
 *
 * ---------------------------------------------------------------------------
 * THE POST ACTION LEFT THE DOCK — 2026-08-24
 *
 * This bar used to carry a raised, red, circular Post button after a hairline
 * separator, on the reasoning that "posting a property is the single thing an
 * owner opens this app to do". Restoring Home made that claim testable against
 * the space available, and it failed twice over.
 *
 * Geometry first. Five destinations plus the action needs about 385pt with the
 * expanding label; a 411dp device offers 379 inside the outer padding and a
 * 360dp device offers 328. It does not fit, and the fix cannot be to shrink
 * the label, because the label is the whole selected state.
 *
 * Product second, and this is the real reason. An owner account is capped at
 * ONE listing, enforced server-side in a transaction. A buyer pressing Post
 * meets an upgrade wall; an owner who already has a listing would be refused,
 * which is why `owner/properties` hides its own add control in that state. So
 * the permanent slot was unusable in the large majority of sessions — the
 * single worst thing to spend a scarce destination on.
 *
 * Posting is not gone and is not harder to reach. It is a card on Home that
 * says something different depending on who is looking: an owner with no
 * listing is invited to post, an owner with one sees it and their leads, and a
 * buyer is told what becoming an owner involves. A permanent button that 400s
 * for most of the people who press it is worse than a card that adapts.
 *
 * With the action gone, this is what a tab bar is supposed to be: destinations
 * only, five of them, no exceptions to explain.
 *
 * ---------------------------------------------------------------------------
 * THE SELECTED TAB IS ACCENT, NOT BRAND — kept from 2026-08-15
 *
 * `colors.ts` says which is which: brand is "the brand mark colour. Not an
 * action colour", accent is "the primary action colour". The selected tab
 * takes the accent. That distinction was introduced when two red objects sat
 * side by side here and the post button appeared to "compete with the
 * navigation"; it outlives the button and stays.
 */

/**
 * Drawn in this order. A registered route absent from this map is skipped,
 * which is what keeps the redirect-only routes (`properties`, `saved`) and the
 * dark `chat` route out of the dock without this file knowing about them.
 *
 * Every icon here is a general-purpose glyph, which the module doc above
 * requires: an inactive tab shows no label, so a domain-specific icon would be
 * unreadable. Magnifier, heart, bell, person.
 */
const TABS: Record<string, { label: string; icon: keyof typeof Ionicons.glyphMap }> = {
  index: { label: 'Home', icon: 'home' },
  search: { label: 'Search', icon: 'search' },
  activity: { label: 'Activity', icon: 'heart' },
  updates: { label: 'Updates', icon: 'notifications' },
  profile: { label: 'Profile', icon: 'person' },
};

const DOCK_HEIGHT = 52;
const ITEM_HEIGHT = 40;
/** `size={22}` in the reference. */
const ICON_SIZE = 22;

/**
 * Ceiling on the expanded label, so a long word cannot push the pill past the
 * screen on a narrow device. The label is single-line and ellipsises into this.
 *
 * Tightened from 72 when the fifth destination arrived. The widest label in the
 * set is "Activity" at roughly 52pt, so 64 clears every real label and leaves
 * the cap doing what it is for — bounding a translation, not truncating
 * English. Five items at 46pt plus one expanded to about 110 plus gaps and
 * padding lands near 328pt, which fits a 360dp screen inside its 16pt outer
 * padding.
 */
const LABEL_MAX_WIDTH = 64;

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

export type TabBarProps = BottomTabBarProps;

export function TabBar({ state, navigation }: TabBarProps) {
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
