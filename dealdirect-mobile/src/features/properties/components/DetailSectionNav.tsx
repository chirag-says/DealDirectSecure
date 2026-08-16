import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Pressable, ScrollView, StyleSheet } from 'react-native';
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

import { gesture, radius, spacing, useTheme } from '@/theme';
import { Text } from '@/ui';
import { HEADER_BAR_HEIGHT, useHeaderProgress } from './DetailHeader';

/**
 * The detail screen's section nav.
 *
 * ---------------------------------------------------------------------------
 * WHY A LONG PAGE NEEDS ONE
 *
 * This screen is several thousand pixels of a single column, and until now the
 * only way to reach the amenities was to scroll past everything before them.
 * Square Yards pins a horizontally-scrolling strip of jump links under its
 * collapsed header for exactly this — About, Price List, Floor Plans, Photos,
 * Amenities, Specifications, Map & Landmarks, RERA, Price Insights, Reviews,
 * FAQs — and it is the single most useful thing on their detail page, because
 * a buyer arrives wanting one specific answer and the page is organised around
 * telling them everything.
 *
 * ---------------------------------------------------------------------------
 * THE SECTIONS ARE MEASURED, NOT DECLARED
 *
 * Which sections a listing has depends on the listing: a commercial unit has no
 * bedrooms table, most rows carry no video, a rental has no EMI block. A
 * hard-coded list of links would therefore scroll people to the wrong place or
 * to nothing at all, which is worse than no nav.
 *
 * So each section reports its own offset through `onLayout` as it renders, and
 * this strip shows whatever registered. A section that did not render has no
 * entry, and the offsets are real measurements rather than an estimate that
 * drifts as the user's text size changes.
 *
 * ---------------------------------------------------------------------------
 * IT APPEARS WITH THE BAR, NOT BEFORE IT
 *
 * Over the photograph there is nothing to navigate away from yet and the strip
 * would be chrome covering the one image the page is selling. It fades and
 * slides in on the same `useHeaderProgress` value that turns the nav bar
 * opaque, so the two arrive as one object rather than as two things that happen
 * to move at similar times.
 *
 * Fewer than two sections and it does not render at all. A nav strip offering
 * one destination is a label pretending to be a control.
 */

export interface DetailSection {
  id: string;
  label: string;
  /** Offset within the scroll content, in points. */
  y: number;
}

export const SECTION_NAV_HEIGHT = 44;

/** Sections nearer the top than this are treated as "the top". */
const ACTIVE_TOLERANCE = 24;

export interface DetailSectionNavProps {
  sections: readonly DetailSection[];
  scrollY: SharedValue<number>;
  /** Scrolls the page. The caller owns the scroll view. */
  onJump: (y: number) => void;
}

export function DetailSectionNav({ sections, scrollY, onJump }: DetailSectionNavProps) {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const progress = useHeaderProgress(scrollY, insets.top);
  const reduceMotion = useReducedMotion();
  const railRef = useRef<ScrollView>(null);

  const [activeIndex, setActiveIndex] = useState(0);
  /**
   * Whether the strip is far enough in to accept touches.
   *
   * Not cosmetic. At `progress` 0 the strip is fully transparent but still
   * occupies a 44pt band directly under the nav bar, over the photograph — so
   * without this, a tap aimed at the top of the hero to open the gallery would
   * land on an invisible control and jump the page instead. Opacity hides a
   * view; it does not stop it eating touches.
   *
   * Crossed to JS on a boolean flip rather than read per frame, same as the
   * header's status-bar switch.
   */
  const [touchable, setTouchable] = useState(false);

  const barHeight = insets.top + HEADER_BAR_HEIGHT;

  const setTouchableFromUI = useCallback((next: boolean) => setTouchable(next), []);

  useAnimatedReaction(
    () => progress.value > 0.9,
    (next, previous) => {
      if (previous !== null && next !== previous) runOnJS(setTouchableFromUI)(next);
    },
    [setTouchableFromUI]
  );

  /**
   * The active chip, computed on the UI thread and crossed to JS only when the
   * INDEX changes.
   *
   * Chip styling is React state, so it cannot be driven by an animated style;
   * mapping it off every scroll frame would post a bridge message sixty times a
   * second to set a value that changes perhaps ten times in a full scroll.
   * Same technique the header uses for its status-bar flip.
   *
   * `offsets` is captured by the worklet, so it re-runs when a section
   * registers — which is what makes the strip correct on first paint rather
   * than only after the user scrolls.
   */
  // Memoised because the reaction below re-registers whenever its dependency
  // identity changes, and a fresh array on every render would tear down and
  // rebuild a UI-thread subscription on each one. `sections` is stable for the
  // same reason — see `useSectionRegistry`.
  const offsets = useMemo(() => sections.map((section) => section.y), [sections]);
  const threshold = barHeight + SECTION_NAV_HEIGHT + ACTIVE_TOLERANCE;

  useAnimatedReaction(
    () => {
      const line = scrollY.value + threshold;
      let index = 0;
      for (let i = 0; i < offsets.length; i += 1) {
        const offset = offsets[i];
        if (offset !== undefined && offset <= line) index = i;
        else break;
      }
      return index;
    },
    (next, previous) => {
      if (previous !== null && next !== previous) runOnJS(setActiveIndex)(next);
    },
    [offsets, threshold]
  );

  /**
   * Keeps the active chip on screen.
   *
   * A strip whose current position is scrolled off to the left is worse than no
   * strip: it says the page is somewhere the user cannot see. Approximated from
   * the index rather than measured per chip — an exact measurement would need
   * an `onLayout` per chip and a second state map, to place a rail that only
   * has to be roughly right.
   */
  useEffect(() => {
    railRef.current?.scrollTo({
      x: Math.max(0, activeIndex * 104 - 80),
      // Under reduced motion it jumps rather than glides. The chip still has to
      // end up on screen — that is comprehension, not decoration — but a strip
      // sliding sideways on its own while the user scrolls vertically is
      // exactly the kind of unrequested movement the setting exists to stop.
      animated: !reduceMotion,
    });
  }, [activeIndex, reduceMotion]);

  /*
   * The fade stays under reduced motion; the slide does not.
   *
   * `theme/motion.ts` states the rule this follows: reduced motion means a
   * gentler, non-vestibular equivalent rather than the absence of feedback, so
   * slides become cross-fades and opacity that carries meaning stays. The
   * opacity here IS the meaning — it is what says the strip has arrived — and
   * the 8pt drop is the part someone with a vestibular trigger does not want.
   *
   * Read on the JS side rather than inside the worklet: the OS setting cannot
   * change mid-scroll, so branching per frame would be re-deciding a constant
   * sixty times a second.
   */
  const containerStyle = useAnimatedStyle(() => ({
    opacity: interpolate(progress.value, [0.7, 1], [0, 1], Extrapolation.CLAMP),
    transform: reduceMotion
      ? []
      : [{ translateY: interpolate(progress.value, [0.7, 1], [-8, 0], Extrapolation.CLAMP) }],
  }));

  const handleJump = useCallback(
    (section: DetailSection) => {
      // Land the section heading just under the chrome rather than at the very
      // top of the scroll view, where the bar and this strip would cover it.
      onJump(Math.max(0, section.y - barHeight - SECTION_NAV_HEIGHT));
    },
    [onJump, barHeight]
  );

  if (sections.length < 2) return null;

  return (
    <Animated.View
      style={[
        {
          position: 'absolute',
          left: 0,
          right: 0,
          top: barHeight,
          height: SECTION_NAV_HEIGHT,
          zIndex: 9,
          backgroundColor: theme.colors.surface,
          borderBottomWidth: StyleSheet.hairlineWidth,
          borderBottomColor: theme.colors.border,
        },
        containerStyle,
      ]}
      pointerEvents={touchable ? 'auto' : 'none'}
    >
      <ScrollView
        ref={railRef}
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={RAIL_STYLE}
      >
        {sections.map((section, index) => {
          const active = index === activeIndex;
          return (
            <Pressable
              key={section.id}
              accessibilityRole="tab"
              accessibilityState={{ selected: active }}
              accessibilityLabel={section.label}
              hitSlop={gesture.hitSlop}
              onPress={() => handleJump(section)}
              // Object, not a function — see `ui/Chip.tsx`. A function-valued
              // `style` is discarded by NativeWind's interop.
              className="active:opacity-60"
              style={{
                justifyContent: 'center',
                paddingHorizontal: spacing.md,
                paddingVertical: 6,
                borderRadius: radius.full,
                backgroundColor: active ? theme.colors.accentMuted : 'transparent',
              }}
            >
              <Text variant="footnote" tone={active ? 'accent' : 'secondary'} numberOfLines={1}>
                {section.label}
              </Text>
            </Pressable>
          );
        })}
      </ScrollView>
    </Animated.View>
  );
}

const RAIL_STYLE = {
  alignItems: 'center',
  gap: spacing.xs,
  paddingHorizontal: spacing.sm,
} as const;

/**
 * Collects section offsets as they render.
 *
 * A map keyed by id rather than an array, because sections register in layout
 * order but a conditional one appearing later must not shift the entries
 * already recorded. The sorted array is derived on read.
 *
 * `register` is stable, so a section can pass it straight to `onLayout` without
 * the whole page re-rendering every time one of them measures. Registering the
 * same id at the same offset is a no-op for the same reason: `onLayout` fires
 * again on rotation, on a text-size change and on any re-measure, and setting
 * state unconditionally there is an easy way to loop.
 */
export function useSectionRegistry() {
  const [sections, setSections] = useState<Record<string, DetailSection>>({});

  const register = useCallback((id: string, label: string, y: number) => {
    setSections((current) => {
      const existing = current[id];
      if (existing && Math.abs(existing.y - y) < 1) return current;
      return { ...current, [id]: { id, label, y } };
    });
  }, []);

  // Memoised so the strip's identity is stable between renders. Without it,
  // every parent render hands `DetailSectionNav` a new array and it rebuilds
  // its UI-thread reaction — sixty times a second while the page is scrolling,
  // which is the one thing this component must not do.
  const ordered = useMemo(
    () => Object.values(sections).sort((a, b) => a.y - b.y),
    [sections]
  );

  return { sections: ordered, register };
}
