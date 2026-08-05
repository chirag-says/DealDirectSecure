import { useCallback } from 'react';
import { View } from 'react-native';

import { radius, spacing } from '@/theme';
import { Rail, Skeleton, useRailItemWidth } from '@/ui';
import { PropertyRailCard, type RailProperty } from './PropertyRailCard';

/**
 * A horizontal row of property cards.
 *
 * The join between `Rail` (scrolling, snapping, gutters) and `PropertyRailCard`
 * (one listing). Every discovery row on Home goes through here, so a change to
 * how properties appear in a rail is one edit rather than nine.
 *
 * There is no empty state. A rail with nothing in it does not render, and the
 * decision to render at all belongs to the caller — `useCollection` makes it
 * from live counts. An "no properties found" box inside a discovery row is a
 * hole in the page that tells the user about a shortcoming they did not ask
 * about and cannot act on.
 */

export interface PropertyRailProps {
  /** Live search results or replayed history. See `RailProperty`. */
  items: readonly RailProperty[];
  loading?: boolean;
  onSelect: (id: string) => void;
  accessibilityLabel?: string;
}

const SKELETON_COUNT = 3;

export function PropertyRail({
  items,
  loading = false,
  onSelect,
  accessibilityLabel,
}: PropertyRailProps) {
  const width = useRailItemWidth('large');

  const renderItem = useCallback(
    (property: RailProperty, itemWidth: number) => (
      <PropertyRailCard property={property} width={itemWidth} onPress={onSelect} />
    ),
    [onSelect]
  );

  if (loading) {
    return (
      <View
        className="flex-row px-base"
        style={{ gap: spacing.md }}
        accessibilityLabel="Loading properties"
      >
        {Array.from({ length: SKELETON_COUNT }, (_, index) => (
          // Matched to the real card's geometry — 168pt of image plus roughly
          // 92pt of text block — so the row does not resize when data lands and
          // shove everything below it up the screen.
          <Skeleton key={index} width={width} height={260} radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (items.length === 0) return null;

  return (
    <Rail
      data={items}
      size="large"
      keyExtractor={(item) => item.id}
      renderItem={renderItem}
      accessibilityLabel={accessibilityLabel}
    />
  );
}
