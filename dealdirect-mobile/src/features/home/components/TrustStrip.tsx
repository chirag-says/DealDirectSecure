import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, useTheme, type Theme } from '@/theme';
import { Text } from '@/ui';

/**
 * The three reasons to trust a listing here, as one quiet strip.
 *
 * Sits directly under the first rail, where someone who has just looked at
 * real inventory is deciding whether to believe it. That placement is the
 * whole point: the same three claims at the bottom of the scroll are read as
 * marketing, and the same three as a full section would outweigh the listings
 * they are meant to support.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE ICONS CARRY COLOUR WHEN ALMOST NOTHING ELSE ON HOME DOES
 *
 * Three different hues on one strip is a real cost on a screen otherwise built
 * from red and neutrals, and it is spent deliberately: these are three
 * unrelated promises, and a shared colour would read as three parts of one
 * claim. Each tint is confined to a 28pt circle, so the strip still reads as
 * grey at arm's length.
 *
 * NO NUMBERS, for the reason set out at length in `AboutDealDirect`: a
 * quantitative claim on this screen can be disproved by the rail directly
 * above it. Every line here is a statement about how the product works.
 */

interface Point {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  body: string;
  /** Resolved against the live theme, so both schemes stay legible. */
  tint: (theme: Theme) => { fg: string; bg: string };
}

const POINTS: readonly Point[] = [
  {
    icon: 'shield-checkmark-outline',
    title: 'Verified Properties',
    body: 'Only genuine listings',
    tint: (theme) => ({ fg: theme.colors.brand, bg: theme.colors.dangerMuted }),
  },
  {
    icon: 'person-circle-outline',
    title: 'Direct Owners',
    body: 'Deal directly, save more',
    tint: (theme) => ({ fg: theme.colors.accent, bg: theme.colors.accentMuted }),
  },
  {
    icon: 'lock-closed-outline',
    title: 'No Hidden Fees',
    body: 'What you see is what you pay',
    tint: (theme) => ({ fg: theme.colors.success, bg: theme.colors.successMuted }),
  },
];

export function TrustStrip() {
  const theme = useTheme();

  return (
    <View
      className="mx-lg flex-row"
      style={{
        paddingVertical: spacing.base,
        paddingHorizontal: spacing.md,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surfaceMuted,
        gap: spacing.sm,
      }}
    >
      {POINTS.map((point) => {
        const { fg, bg } = point.tint(theme);

        return (
          <View key={point.title} className="flex-1 flex-row items-start" style={{ gap: spacing.sm }}>
            <View
              className="items-center justify-center"
              style={{
                width: 28,
                height: 28,
                borderRadius: radius.full,
                backgroundColor: bg,
              }}
            >
              <Ionicons name={point.icon} size={15} color={fg} />
            </View>

            <View className="flex-1">
              {/*
                Three columns on a 360pt screen leaves roughly 90pt each, and
                these titles do not fit on one line there. Wrapping is correct
                and clipping is not, so nothing here is truncated.
              */}
              <Text variant="caption" style={{ fontWeight: '600' }}>
                {point.title}
              </Text>
              <Text variant="caption" tone="muted" className="mt-xs">
                {point.body}
              </Text>
            </View>
          </View>
        );
      })}
    </View>
  );
}
