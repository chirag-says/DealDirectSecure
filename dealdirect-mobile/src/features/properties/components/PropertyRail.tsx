import { useCallback, useState } from 'react';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
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
 * from live counts. A "no properties found" box inside a discovery row is a
 * hole in the page that tells the user about a shortcoming they did not ask
 * about and cannot act on.
 */

export interface PropertyRailProps {
  /** Live search results or replayed history. See `RailProperty`. */
  items: readonly RailProperty[];
  loading?: boolean;
  onSelect: (id: string) => void;
  accessibilityLabel?: string;
  /** Page dots under the row. Off by default; only Home asks for them. */
  showIndicator?: boolean;
}

const SKELETON_COUNT = 3;

/** Beyond this the dots stop being countable and start being texture. */
const MAX_DOTS = 6;

export function PropertyRail({
  items,
  loading = false,
  onSelect,
  accessibilityLabel,
  showIndicator = false,
}: PropertyRailProps) {
  const width = useRailItemWidth('large');
  const [index, setIndex] = useState(0);

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
        {Array.from({ length: SKELETON_COUNT }, (_, i) => (
          // Matched to the real card's geometry — 180pt of image plus roughly
          // 116pt of text block — so the row does not resize when data lands
          // and shove everything below it up the screen.
          <Skeleton key={i} width={width} height={296} radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (items.length === 0) return null;

  return (
    <View>
      <Rail
        data={items}
        size="large"
        keyExtractor={(item) => item.id}
        renderItem={renderItem}
        accessibilityLabel={accessibilityLabel}
        onIndexChange={showIndicator ? setIndex : undefined}
      />

      {/*
        One dot per card up to a ceiling, and nothing at all for a single card
        — an indicator showing one page communicates only that there is no more
        to see, which the absent second card already said.

        Decorative and hidden from screen readers: the row it describes is
        already traversable item by item, and a reader announcing "page 2 of 6"
        alongside that is duplicate navigation.
      */}
      {showIndicator && items.length > 1 ? (
        <Indicator count={Math.min(items.length, MAX_DOTS)} active={Math.min(index, MAX_DOTS - 1)} />
      ) : null}
    </View>
  );
}

function Indicator({ count, active }: { count: number; active: number }) {
  const theme = useTheme();

  return (
    <View
      className="mt-md flex-row items-center justify-center"
      style={{ gap: spacing.xs + 1 }}
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      pointerEvents="none"
    >
      {Array.from({ length: count }, (_, i) => {
        const isActive = i === active;

        return (
          <View
            key={i}
            style={{
              // The active dot stretches into a dash rather than growing into
              // a bigger circle: length reads as "you are here" without the
              // row appearing to change size as you scroll.
              width: isActive ? 18 : 6,
              height: 4,
              borderRadius: radius.full,
              backgroundColor: isActive ? theme.colors.brand : theme.colors.border,
            }}
          />
        );
      })}
    </View>
  );
}
