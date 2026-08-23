import Ionicons from '@expo/vector-icons/Ionicons';
import type { BottomTabBarProps } from '@react-navigation/bottom-tabs';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useDerivedValue,
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
 * THE WIDTH BUDGET IS FIXED AT ONE LABEL, AND THE DOCK OWNS IT — 2026-08-24
 *
 * The bug this fixes: switching tabs showed both pills expanded at once,
 * colliding and clipping.
 *
 * The cause was not the animation curves. It was that each `TabItem` owned its
 * own `shape` value and animated its own WIDTH, with nothing anywhere
 * constraining the SUM of those widths — while the dock hugged its children
 * (`alignSelf: 'center'`, no width). Three consequences, all of them layout:
 *
 *   1. Two children grew and shrank independently, so the total could exceed
 *      the resting width. `maxWidth: '100%'` then made Yoga compress the
 *      children to fit, which is the clipping.
 *   2. Because the dock hugs and centres, its own frame was recomputed every
 *      frame and its left edge moved, sliding every sibling sideways WHILE
 *      they were morphing. That is the "fighting for layout space".
 *   3. `SPRING_LABEL` is underdamped — damping 32 against stiffness 350 is a
 *      ratio of 0.855 — so the growing label overshoots past its measured
 *      width before settling. Two overshooting springs make the peak worse
 *      than the arithmetic suggests, and an interrupted switch leaves three
 *      tabs with non-zero width at once.
 *
 * The fix is a single source of truth for the geometry. The dock holds one
 * transition — a snapshot distribution `fromDist`, a `toIndex`, and a progress
 * `t` — and every tab DERIVES its expansion from it:
 *
 *     expansion(i) = fromDist[i] + ((i === toIndex ? 1 : 0) - fromDist[i]) * t
 *
 * The sum over all tabs is then `Σfrom + (1 - Σfrom) * t`, and since every
 * distribution this produces sums to 1, that is **exactly 1 for any t** —
 * including t > 1 while the spring overshoots, because the overshoot multiplies
 * a set of deltas that already sum to zero. The width budget cannot bulge. It
 * is not a tuning that makes collision unlikely; it is arithmetic that makes it
 * impossible.
 *
 * Interruption is handled by the snapshot: retargeting samples the CURRENT
 * distribution as it is being painted and animates from there, so a tap
 * mid-flight retargets continuously and never jumps. Three tabs may hold
 * fractional widths at once and their total is still one label.
 *
 * Every label shares ONE slot width — the widest measured label — so the total
 * content width is `constant + slot * 1`, identical in every state. The dock
 * therefore never resizes at all, at rest or in motion, which removes the
 * re-centring in (2). Space is handed from the shrinking pill to the growing
 * one and the icons between them slide across to follow it, which is what a
 * physical segmented control does.
 *
 * WHAT MOVED BETWEEN THE THREE CURVES: `marginLeft` used to animate on the ink
 * timing. Margin is layout, so it now animates on the expansion with the width;
 * leaving it on a separate curve would have put a second, unconstrained
 * quantity back into the budget. Ink keeps the label's opacity, colour keeps
 * the icon crossfade, and both are free to run on their own timings because
 * neither occupies space. The pill background follows the expansion rather
 * than the colour timing, which is what guarantees a shrinking pill cannot
 * still be painting a full-strength background while the next one arrives.
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
 * THE DOCK'S FIXED GEOMETRY, stated once.
 *
 * These are the same numbers the styles below apply, pulled out so the
 * available-width clamp cannot drift from the layout it is protecting. If a
 * padding changes down there and not here, the dock starts overflowing again
 * on narrow devices and nothing catches it.
 *
 * An inactive item is `max(minimum touch target, horizontal padding + icon)`.
 */
const ITEM_BASE_WIDTH = Math.max(touchTarget.min, spacing.md * 2 + ICON_SIZE);
/** Between items, from the dock's `gap`. */
const ITEM_GAP = spacing.xs;
/** The dock's own left+right padding. */
const DOCK_PADDING = spacing.sm * 2;
/** The gap between an expanded label and its icon. */
const LABEL_MARGIN = spacing.sm;
/** The outer container's left+right padding, outside the pill. */
const SCREEN_PADDING = spacing.base * 2;

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
 * Narrower than this and the label is dropped rather than truncated.
 *
 * Roughly four characters at footnote size. Under it the expanded tab shows a
 * stub — "Ac…" — which communicates less than the icon does and looks broken.
 */
const LABEL_LEGIBILITY_FLOOR = 32;

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

/**
 * The expansion each tab should have, part-way through a transition.
 *
 * Shared by the dock (to snapshot the current state before retargeting) and by
 * every tab (to derive its own width), so the two can never disagree about the
 * geometry. Marked `worklet` because tabs call it on the UI thread.
 *
 * Any distribution this returns sums to 1 when `from` does, which is the
 * invariant the whole dock rests on — see the module doc.
 */
function expansionFor(from: readonly number[], toIndex: number, t: number, index: number): number {
  'worklet';
  const start = from[index] ?? 0;
  const target = index === toIndex ? 1 : 0;
  const value = start + (target - start) * t;
  // Clamped only against spring overshoot, which is a few percent. It can raise
  // a value that undershot below zero and lower one that overshot past one; in
  // both cases it moves the total TOWARDS 1, never away from it.
  return value < 0 ? 0 : value > 1 ? 1 : value;
}

/** The dock's transition, handed to every tab so they share one geometry. */
interface TabTransition {
  t: SharedValue<number>;
  toIndex: SharedValue<number>;
  fromDist: SharedValue<number[]>;
}

export type TabBarProps = BottomTabBarProps;

export function TabBar({ state, navigation }: TabBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  const visible = state.routes.filter((route) => TABS[route.name]);
  const count = visible.length;

  /**
   * Which of the VISIBLE tabs is selected.
   *
   * `state.index` indexes `state.routes`, which includes the redirect-only and
   * dark routes this bar filters out, so it cannot be used directly. A focused
   * route that is not in the bar — the moment a `dealdirect://properties` link
   * lands on its redirect — gives -1, and the dock deliberately holds its last
   * state through it rather than collapsing every pill for a frame.
   */
  const focusedKey = state.routes[state.index]?.key;
  const activeIndex = visible.findIndex((route) => route.key === focusedKey);

  /**
   * THE ONE TRANSITION. See the module doc for why this lives here rather than
   * inside each tab.
   *
   * `fromDist` is where every tab was when the current transition began,
   * `toIndex` is where the expansion is going, and `t` walks between them.
   */
  const t = useSharedValue(1);
  const toIndex = useSharedValue(activeIndex);
  const fromDist = useSharedValue<number[]>(
    Array.from({ length: count }, (_, i) => (i === activeIndex ? 1 : 0))
  );

  useEffect(() => {
    if (activeIndex < 0) return;
    if (toIndex.value === activeIndex) return;

    // Sample the distribution AS IT IS BEING PAINTED, then animate from there.
    // This is what makes an interrupted switch continuous: a tab caught
    // half-expanded keeps its exact width and carries on from it, instead of
    // snapping to a fresh 0 or 1.
    fromDist.value = Array.from({ length: count }, (_, i) =>
      expansionFor(fromDist.value, toIndex.value, t.value, i)
    );
    toIndex.value = activeIndex;

    t.value = 0;
    t.value = reduceMotion ? 1 : withSpring(1, SPRING_LABEL);
  }, [activeIndex, count, reduceMotion, fromDist, toIndex, t]);

  /**
   * One slot width for every label, so the content width is the same in every
   * state and the dock never resizes.
   *
   * Measured from the labels themselves rather than hard-coded: the widest of
   * them decides, capped so a long translation cannot push the dock off-screen.
   * Until the first measurement lands the slot is 0, which simply means no tab
   * shows a label yet — that happens once, under the dock's entrance.
   */
  const [labelWidths, setLabelWidths] = useState<Record<string, number>>({});

  const reportLabelWidth = useCallback((name: string, width: number) => {
    setLabelWidths((current) =>
      current[name] === width ? current : { ...current, [name]: width }
    );
  }, []);

  /**
   * The width the dock is allowed to occupy, and the slot that fits inside it.
   *
   * ---------------------------------------------------------------------------
   * THIS IS THE CONSTRAINT THAT WAS MISSING, AND THE ONE THAT CAUSED THE BUG
   *
   * React Native children default to `flexShrink: 0`. When a row's content is
   * wider than its container they do NOT compress to fit the way a browser's
   * flexbox would — they overflow, and since this container is a rounded pill
   * with no `overflow: 'hidden'`, they spill past its edge and over each other.
   * That is the collision, and it is absolute rather than relative: it depends
   * on the device width, not on the animation.
   *
   * The arithmetic, with five tabs: 5 items at 46 plus four 4pt gaps plus 16pt
   * of dock padding plus an 8pt label margin is 270pt before the label. A 52pt
   * label makes 322, which fits a 360dp screen with 6pt to spare and does NOT
   * fit a 320dp one. Raise the system font size and the label measures wider
   * still, and a 360dp screen overflows too. The previous dock — four tabs, a
   * separator and the post action — came to almost exactly the same number and
   * had the same failure.
   *
   * So the slot is clamped to what is genuinely left over. On a narrow device
   * or at a large text size the label simply gets less room and ellipsises,
   * which is a legible degradation; overflowing the pill is not. `LABEL_MAX_WIDTH`
   * still applies as the design ceiling.
   */
  const { width: windowWidth } = useWindowDimensions();

  const labelSlot = useMemo(() => {
    const measured = Object.values(labelWidths);
    if (measured.length === 0) return 0;

    const fixed =
      count * ITEM_BASE_WIDTH +
      Math.max(0, count - 1) * ITEM_GAP +
      DOCK_PADDING +
      LABEL_MARGIN;
    const available = windowWidth - SCREEN_PADDING - fixed;
    const slot = Math.min(LABEL_MAX_WIDTH, Math.max(...measured), available);

    /*
      Below the legibility floor, drop the label entirely rather than shipping
      a stub of one.

      A 320dp device leaves about 18pt for the label, which renders "A…" — a
      selected state that says less than the icon above it already does and
      reads as a rendering fault. The dock's own doc explains that every glyph
      here is deliberately conventional precisely so it can stand alone, so
      icon-only is a state this design already supports. The accessibility
      label is unaffected: a screen reader announces the destination either way.
    */
    return slot < LABEL_LEGIBILITY_FLOOR ? 0 : Math.max(0, slot);
  }, [labelWidths, count, windowWidth]);

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
          //
          // Hugging is only safe because the content width is now INVARIANT:
          // one shared label slot times an expansion budget that always sums to
          // one. Yoga measures the same width every frame, so the dock has
          // nothing to re-centre. It was not safe before, and that was the bug.
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
        {visible.map((route, index) => {
          const spec = TABS[route.name];
          if (!spec) return null;

          return (
            <TabItem
              key={route.key}
              spec={spec}
              index={index}
              focused={index === activeIndex}
              reduceMotion={reduceMotion}
              labelSlot={labelSlot}
              onMeasureLabel={reportLabelWidth}
              transition={{ t, toIndex, fromDist }}
              onPress={() => {
                // `navigate`, not a raw dispatch, so a repeat visit returns to
                // the existing screen instead of pushing a duplicate of it.
                //
                // Only ever called for a tab that is NOT already selected —
                // `TabItem` withholds the handler while focused.
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
 * IT NO LONGER OWNS ITS OWN WIDTH — rewritten 2026-08-24
 *
 * The previous version kept a per-tab `shape` spring and animated its label
 * width from it. That is what let two tabs claim width at the same time, with
 * nothing able to see both — the collision described in the module doc.
 *
 * Width is now DERIVED, not owned. `expansion` reads the dock's one transition
 * and computes this tab's share of a budget that always totals one label. A tab
 * cannot widen itself; it can only be given more of the budget as another gives
 * its share back, which is the coordination the bug was missing.
 *
 * What each curve drives now, and why:
 *
 *   expansion  spring   width, margin, pill opacity. Everything that OCCUPIES
 *                       SPACE, plus the background, so a pill cannot still be
 *                       painting at full strength while it hands its width over.
 *   ink        timing   label opacity. Free-running: text that fades does not
 *                       take up room, so it cannot affect the budget.
 *   colour     timing   icon crossfade and label colour. Also free-running,
 *                       for the same reason.
 *
 * The label stays MOUNTED in every state — no conditional render, no
 * `FadeIn`/`FadeOut`, no `LinearTransition`. Its width is animated directly,
 * so the pill's size is a consequence of the label rather than a separate
 * measured animation chasing it, and an interrupted switch simply retargets.
 */
function TabItem({
  spec,
  index,
  focused,
  reduceMotion,
  labelSlot,
  transition,
  onMeasureLabel,
  onPress,
}: {
  spec: { label: string; icon: keyof typeof Ionicons.glyphMap };
  index: number;
  focused: boolean;
  reduceMotion: boolean;
  /** Shared by every tab, so the content width is identical in every state. */
  labelSlot: number;
  transition: TabTransition;
  onMeasureLabel: (name: string, width: number) => void;
  onPress: () => void;
}) {
  const theme = useTheme();
  const { t, toIndex, fromDist } = transition;

  /**
   * This tab's share of the width budget.
   *
   * Derived on the UI thread from the dock's transition, so it is always
   * consistent with every sibling's share by construction rather than by
   * timing. See `expansionFor` and the module doc.
   */
  const expansion = useDerivedValue(() =>
    expansionFor(fromDist.value, toIndex.value, t.value, index)
  );

  /**
   * The two free-running curves.
   *
   * Neither occupies space, so neither needs to be part of the shared budget —
   * which is exactly why they are allowed to keep their own timings and their
   * own start points. They are also what stops the handoff reading as a hard
   * cut: the label fades slightly ahead of the width closing, and the icon
   * crossfades independently of both.
   */
  const ink = useSharedValue(focused ? 1 : 0);
  const colour = useSharedValue(focused ? 1 : 0);

  useEffect(() => {
    const to = focused ? 1 : 0;
    if (reduceMotion) {
      ink.value = to;
      colour.value = to;
      return;
    }
    ink.value = withTiming(to, { duration: INK_MS });
    colour.value = withTiming(to, { duration: COLOR_MS });
  }, [focused, reduceMotion, ink, colour]);

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
   * Driven by `expansion` rather than by the colour timing, so the background
   * is exactly as strong as the pill is wide. Two pills can therefore never
   * both look active: their opacities sum to the same one as their widths.
   */
  const pillStyle = useAnimatedStyle(() => ({ opacity: expansion.value }));

  /**
   * Width and margin from the shared budget; opacity from ink.
   * `overflow: 'hidden'` is what makes a width change read as a reveal rather
   * than a squash.
   */
  const labelStyle = useAnimatedStyle(
    () => ({
      width: labelSlot * expansion.value,
      marginLeft: spacing.sm * expansion.value,
      opacity: ink.value,
    }),
    [labelSlot]
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
              PINNED to the slot width, and this is the fix for the label
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
            width: labelSlot || undefined,
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
        twice. Its width is reported up to the dock, which takes the widest and
        hands the same slot back to every tab.
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
            if (measured > 0) onMeasureLabel(spec.label, measured);
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
