import React from 'react';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
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

export function ProgressBar({ value, tone = 'accent', size = 'md', label }: ProgressBarProps) {
  const theme = useTheme();
  const pct = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));

  const fill =
    tone === 'success' ? theme.colors.success : tone === 'brand' ? theme.colors.brand : theme.colors.accent;

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
        <View
          style={{
            width: `${pct * 100}%`,
            height: '100%',
            borderRadius: radius.full,
            backgroundColor: fill,
          }}
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
}

/**
 * Mutually exclusive choice between a small number of views.
 *
 * `accessibilityRole="tab"` on the segments and `tablist` on the container:
 * these switch what is displayed rather than performing an action, and a
 * screen reader announcing "button" gives no clue that one of them is already
 * selected. The two implementations this replaces disagreed on exactly this —
 * one used `tab`, the other `button`.
 */
export function Segmented<T extends string>({ options, value, onChange }: SegmentedProps<T>) {
  const theme = useTheme();

  return (
    <View
      accessibilityRole="tablist"
      className="flex-row"
      style={{
        padding: spacing.xs,
        borderRadius: radius.md,
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
              flex: 1,
              paddingVertical: spacing.sm,
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: radius.sm,
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
            <Text variant={selected ? 'bodyEmphasis' : 'callout'} tone={selected ? 'primary' : 'secondary'}>
              {option.label}
            </Text>
          </PressableScale>
        );
      })}
    </View>
  );
}
