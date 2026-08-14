import React, { useEffect } from 'react';
import { View } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';

import { radius, reducedMotion, spacing, spring, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * Numbers on a screen: stat tiles, progress, and segmented choice.
 *
 * Each of these existed twice in the app under two different names before
 * 2026-08-13 — `SummaryTile` in owner analytics and `StatTile` in the campaign
 * screen; two progress bars, one in rewards and one in the listing wizard; two
 * segmented controls, one on Saved and one in the Home hero, disagreeing on
 * radius, fill, sizing and accessibility role.
 */

// --- Stat -----------------------------------------------------------------

export interface StatProps {
  label: string;
  value: string | number;
  /** Context under the value: a delta, a period, a denominator. */
  detail?: string;
  onPress?: () => void;
  /** Fills the tile with the accent's muted tint, for the one that matters most. */
  emphasis?: boolean;
}

/**
 * A single measurement.
 *
 * The value leads and the label follows, not the other way round. On a
 * dashboard the user is scanning for magnitudes; making them read a label to
 * find the number inverts the work. Tabular figures so a column of stats keeps
 * its digits in line.
 */
export function Stat({ label, value, detail, onPress, emphasis = false }: StatProps) {
  const theme = useTheme();

  const body = (
    <View
      style={{
        flex: 1,
        padding: spacing.base,
        borderRadius: radius.lg,
        backgroundColor: emphasis ? theme.colors.accentMuted : theme.colors.surface,
      }}
    >
      <Text
        variant="title2"
        tone={emphasis ? 'accent' : 'primary'}
        style={{ fontVariant: ['tabular-nums'] }}
        numberOfLines={1}
      >
        {value}
      </Text>
      <Text variant="footnote" tone="secondary" numberOfLines={2} style={{ marginTop: 2 }}>
        {label}
      </Text>
      {detail ? (
        <Text variant="caption" tone="muted" numberOfLines={1} style={{ marginTop: spacing.xs }}>
          {detail}
        </Text>
      ) : null}
    </View>
  );

  if (!onPress) return body;
  return (
    <PressableScale accessibilityRole="button" accessibilityLabel={`${label}, ${value}`} onPress={onPress} style={{ flex: 1 }}>
      {body}
    </PressableScale>
  );
}

/** Lays stats out in even rows. Two per row reads better than three on a phone. */
export function StatRow({ children }: { children: React.ReactNode }) {
  return <View className="flex-row" style={{ gap: spacing.md }}>{children}</View>;
}

// --- Progress -------------------------------------------------------------

export interface ProgressBarProps {
  /** 0–1. Clamped, so a caller's bad arithmetic cannot overflow the track. */
  value: number;
  tone?: 'accent' | 'success' | 'brand';
  /** Thicker bars read as a primary element; thin ones as an annotation. */
  size?: 'sm' | 'md';
  label?: string;
}

/**
 * ---------------------------------------------------------------------------
 * IT ANIMATES, AND IT ANIMATES `scaleX` RATHER THAN `width`
 *
 * Two separate reasons, and the second is the one that is easy to get wrong.
 *
 * **Why it animates at all.** The bar's whole job is showing how close to a
 * limit you are, and the moment that matters is the one where the number
 * CHANGES — removing an interest on the Saved screen frees one of five capped
 * slots. Teleporting to the new width tells you the value; moving to it tells
 * you the value changed and by how much, which is the question the user asked
 * by tapping Remove.
 *
 * **Why not `width`.** Animating width re-runs layout on every frame, which
 * runs on the main thread and cannot be offloaded. A transform is composited on
 * the UI thread and costs nothing per frame. So the fill is laid out at FULL
 * width once and scaled down, with `transformOrigin` pinned left so it grows
 * from the start of the track rather than from its middle.
 *
 * A spring rather than a timing curve, per `theme/motion.ts`: the value can
 * change again while the bar is still moving (removing two interests in a row),
 * and a spring retargets from wherever it currently is instead of snapping.
 * `spring.standard` is critically damped — a progress bar that overshoots is
 * briefly showing a number that is not true.
 */
export function ProgressBar({ value, tone = 'accent', size = 'md', label }: ProgressBarProps) {
  const theme = useTheme();
  const reduceMotion = useReducedMotion();
  const pct = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));

  const fill =
    tone === 'success' ? theme.colors.success : tone === 'brand' ? theme.colors.brand : theme.colors.accent;

  const progress = useSharedValue(pct);

  useEffect(() => {
    progress.value = reduceMotion
      ? withTiming(pct, { duration: reducedMotion.crossfade })
      : withSpring(pct, spring.standard);
  }, [pct, reduceMotion, progress]);

  const fillStyle = useAnimatedStyle(() => ({ transform: [{ scaleX: progress.value }] }));

  return (
    <View
      accessibilityRole="progressbar"
      accessibilityValue={{ min: 0, max: 100, now: Math.round(pct * 100) }}
      accessibilityLabel={label}
    >
      <View
        style={{
          height: size === 'sm' ? 4 : 8,
          borderRadius: radius.full,
          backgroundColor: theme.colors.surfaceMuted,
          overflow: 'hidden',
        }}
      >
        <Animated.View
          style={[
            {
              width: '100%',
              height: '100%',
              borderRadius: radius.full,
              backgroundColor: fill,
              // Without this the fill scales about its centre, so an empty bar
              // is a stub floating in the middle of the track rather than
              // nothing at its start.
              transformOrigin: 'left',
            },
            fillStyle,
          ]}
        />
      </View>
    </View>
  );
}

// --- Segmented ------------------------------------------------------------

export interface SegmentedOption<T extends string> {
  label: string;
  value: T;
}

export interface SegmentedProps<T extends string> {
  options: readonly SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  /**
   * Sizes each segment to its label instead of dividing the container evenly,
   * and takes a pill radius rather than the rounded-rectangle one.
   *
   * The default shape assumes the control OWNS its row — it fills the width and
   * divides it equally, which is right when it is switching what a whole screen
   * shows. The compact shape is for a control sharing a row with other things,
   * where a full-width track would push everything after it off screen; the
   * search screen's quick-filter rail is the case that needed it.
   *
   * Equal widths are the better default and are kept as one: they give every
   * option the same target size and stop the control reflowing when a label
   * changes. Compact trades that away for the horizontal room, which is only
   * worth it when the room is genuinely scarce.
   */
  compact?: boolean;
  /** Spoken before the selected option, e.g. "Listing type". */
  accessibilityLabel?: string;
}

/**
 * Mutually exclusive choice between a small number of views.
 *
 * `accessibilityRole="tab"` on the segments and `tablist` on the container:
 * these switch what is displayed rather than performing an action, and a
 * screen reader announcing "button" gives no clue that one of them is already
 * selected. The two implementations this replaces disagreed on exactly this —
 * one used `tab`, the other `button`.
 *
 * A segmented control and a row of `Chip`s look similar and mean different
 * things. Chips are independent — each is on or off, several can be on, and
 * none-selected is normal. This is ONE value with N spellings: exactly one is
 * always selected, and choosing another deselects the old one for you. Reach
 * for this whenever that second sentence is the true one.
 */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  compact = false,
  accessibilityLabel,
}: SegmentedProps<T>) {
  const theme = useTheme();

  return (
    <View
      accessibilityRole="tablist"
      accessibilityLabel={accessibilityLabel}
      className="flex-row"
      style={{
        padding: spacing.xs,
        borderRadius: compact ? radius.full : radius.md,
        backgroundColor: theme.colors.surfaceMuted,
      }}
    >
      {options.map((option) => {
        const selected = option.value === value;
        return (
          <PressableScale
            key={option.value}
            accessibilityRole="tab"
            accessibilityState={{ selected }}
            accessibilityLabel={option.label}
            onPress={() => onChange(option.value)}
            activeScale={0.98}
            style={{
              ...(compact
                ? { paddingHorizontal: spacing.md, paddingVertical: 6 }
                : { flex: 1, paddingVertical: spacing.sm }),
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: compact ? radius.full : radius.sm,
              // The selected segment is the RAISED one — it comes forward out
              // of the well, which is what a physical segmented control does.
              backgroundColor: selected ? theme.colors.surface : 'transparent',
              ...(selected
                ? {
                    shadowColor: '#000',
                    shadowOpacity: 0.08,
                    shadowRadius: 4,
                    shadowOffset: { width: 0, height: 1 },
                    elevation: 2,
                  }
                : null),
            }}
          >
            <Text
              variant={
                compact
                  ? selected
                    ? 'subhead'
                    : 'footnote'
                  : selected
                    ? 'bodyEmphasis'
                    : 'callout'
              }
              tone={selected ? 'primary' : 'secondary'}
              numberOfLines={1}
              style={compact && selected ? { fontWeight: '600' } : undefined}
            >
              {option.label}
            </Text>
          </PressableScale>
        );
      })}
    </View>
  );
}
