import Ionicons from '@expo/vector-icons/Ionicons';
import React from 'react';
import { View } from 'react-native';

import { gesture, radius, screenPadding, spacing, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * A titled Home section, with an optional "View all".
 *
 * Home is a stack of these, so the heading treatment, the gap above it and the
 * action alignment are decided once. Repeating that per section is how the
 * fourth one ends up 4px off and the page starts reading as assembled rather
 * than designed.
 *
 * The action is a real target with a chevron, not bare coloured text: on a
 * screen that is entirely navigation, the affordance has to be unambiguous.
 *
 * "View all" reads in `textPrimary`, not the app's blue `accent`. Blue is the
 * action colour everywhere else in the app; on Home it would be the second
 * colour competing with the brand red for attention, on a screen whose brief
 * is a restrained, mostly-red-mostly-neutral palette. The chevron alone
 * carries a hint of brand red, which is enough to mark the row as tappable
 * without spending a second hue on it.
 */

export interface SectionProps {
  title: string;
  /** Optional one-line clarification under the title. */
  subtitle?: string;
  actionLabel?: string;
  onAction?: () => void;
  children: React.ReactNode;
}

export function Section({ title, subtitle, actionLabel, onAction, children }: SectionProps) {
  const theme = useTheme();

  return (
    <View style={{ paddingTop: spacing['2xl'] }}>
      <View
        className="flex-row items-end justify-between"
        // `screenPadding`, matching the rail's own gutter below it. This was
        // `px-lg` (20) while `Rail` padded its content at 16, so every section
        // heading sat 4pt outside the first card it introduced.
        style={{ paddingHorizontal: screenPadding }}
      >
        <View className="flex-1 pr-md">
          <Text variant="title2">{title}</Text>
          {subtitle ? (
            <Text variant="footnote" tone="muted" className="mt-xs">
              {subtitle}
            </Text>
          ) : null}
        </View>

        {/*
          A tinted pill, not bare coloured text with a chevron.
          Text-plus-chevron floating beside a heading reads as part of the
          heading rather than as a control — it was the only tappable thing in
          this row with nothing to say so, and it painted about 18pt tall
          against a 44pt minimum. The pill gives it a real edge and a real
          target.
        */}
        {actionLabel && onAction ? (
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel={`${actionLabel}, ${title}`}
            hitSlop={gesture.hitSlop}
            onPress={onAction}
            activeScale={0.95}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              paddingHorizontal: spacing.md,
              paddingVertical: spacing.xs,
              borderRadius: radius.full,
              backgroundColor: theme.colors.brandMuted,
            }}
          >
            <Text variant="footnote" style={{ color: theme.colors.brand, fontWeight: '600' }}>
              {actionLabel}
            </Text>
            <Ionicons
              name="chevron-forward"
              size={13}
              color={theme.colors.brand}
              style={{ marginLeft: 1 }}
            />
          </PressableScale>
        ) : null}
      </View>

      <View style={{ paddingTop: spacing.base }}>{children}</View>
    </View>
  );
}
