import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Text, formatPrice } from '@/ui';
import { trendBars } from '../format';
import type { LocalityTrendPoint } from '@/types/backend/locality';

/**
 * The quarterly trend, as bars made of Views.
 *
 * ---------------------------------------------------------------------------
 * NO CHART LIBRARY, FOR THE THIRD TIME
 *
 * `app/owner/analytics.tsx` sizes its bars with plain Views and says why: five
 * numbers and a breakdown do not justify a dependency. This is four to eight
 * numbers with no axes, no tooltips, no interaction and no animation. A charting
 * library would add a native or near-native dependency, a rebuild of the dev
 * client, and a second visual language, to draw six rectangles.
 *
 * ---------------------------------------------------------------------------
 * THE NUMBER IS PRINTED, THE BAR IS THE SHAPE
 *
 * `trendBars` scales from just below the minimum rather than from zero, which
 * is the only way four medians within a few percent of each other show any
 * shape at all. That is also exactly the trick a misleading chart plays, so
 * the median is printed under every bar. A reader who only looks at the bars
 * sees the direction; a reader who reads the numbers sees the size. Neither is
 * misled, because the numbers are right there.
 */

export interface TrendBarsProps {
  trend: readonly LocalityTrendPoint[];
}

const BAR_AREA = 96;
const MIN_BAR = 6;

export function TrendBars({ trend }: TrendBarsProps) {
  const theme = useTheme();
  const bars = trendBars(trend);

  if (bars.length === 0) return null;

  return (
    <View>
      <View className="flex-row items-end" style={{ height: BAR_AREA, gap: spacing.sm }}>
        {bars.map((bar, index) => {
          const isLatest = index === bars.length - 1;

          return (
            <View key={bar.period} className="flex-1 items-center justify-end">
              <View
                accessible
                accessibilityLabel={`${bar.label}: ${formatPrice(bar.medianAsking)} from ${bar.count} listings`}
                style={{
                  width: '100%',
                  height: Math.max(MIN_BAR, bar.height * BAR_AREA),
                  borderRadius: radius.sm,
                  // The current quarter carries the accent; the history behind
                  // it is quieter, so the eye lands on where things are now.
                  backgroundColor: isLatest ? theme.colors.accent : theme.colors.surfaceMuted,
                }}
              />
            </View>
          );
        })}
      </View>

      <View className="mt-sm flex-row" style={{ gap: spacing.sm }}>
        {bars.map((bar) => (
          <View key={bar.period} className="flex-1 items-center">
            <Text variant="caption" tone="secondary" numberOfLines={1}>
              {formatPrice(bar.medianAsking)}
            </Text>
            <Text variant="caption" tone="muted" numberOfLines={1}>
              {bar.label}
            </Text>
          </View>
        ))}
      </View>
    </View>
  );
}
