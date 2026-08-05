import { useRouter } from 'expo-router';
import { useCallback } from 'react';
import { FlatList, View, type ListRenderItemInfo } from 'react-native';

import { spacing } from '@/theme';
import { Text } from '@/ui';
import type { PropertySummary } from '../types';
import { PropertyCard } from './PropertyCard';
import { PropertyCardSkeleton } from './PropertyCardSkeleton';

/**
 * A horizontal run of properties, for Home.
 *
 * The SAME `PropertyCard` as the vertical feed, in a different container. The
 * alternative — a purpose-built compact card — means two components that drift
 * apart until the price is formatted one way on Home and another in search
 * results, which is exactly the duplication this app is meant to avoid.
 *
 * Cards are given a fixed width and the row is snapped to it, so a card is
 * never left half-visible at rest. A partially clipped card at the edge is the
 * standard signal that more exists sideways, but stopping ON one is sloppy.
 */

const CARD_WIDTH = 268;
const SNAP_INTERVAL = CARD_WIDTH + spacing.md;

export interface PropertyStripProps {
  items: PropertySummary[];
  loading: boolean;
  /** Shown in place of the row when loading finishes with nothing. */
  emptyLabel?: string;
}

const keyExtractor = (item: PropertySummary) => item.id;

export function PropertyStrip({ items, loading, emptyLabel }: PropertyStripProps) {
  const router = useRouter();

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  const renderItem = useCallback(
    ({ item }: ListRenderItemInfo<PropertySummary>) => (
      <View style={{ width: CARD_WIDTH }}>
        <PropertyCard property={item} onPress={openProperty} />
      </View>
    ),
    [openProperty]
  );

  if (loading) {
    return (
      <View className="flex-row gap-md px-base">
        {[0, 1].map((index) => (
          <View key={index} style={{ width: CARD_WIDTH }}>
            <PropertyCardSkeleton />
          </View>
        ))}
      </View>
    );
  }

  if (items.length === 0) {
    return emptyLabel ? (
      <Text variant="footnote" tone="muted" className="px-base">
        {emptyLabel}
      </Text>
    ) : null;
  }

  return (
    <FlatList
      horizontal
      data={items}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      showsHorizontalScrollIndicator={false}
      contentContainerStyle={ROW_STYLE}
      snapToInterval={SNAP_INTERVAL}
      decelerationRate="fast"
      // A horizontal row inside a vertical scroll view: without this the parent
      // steals the gesture on any drag that is not almost perfectly sideways.
      directionalLockEnabled
    />
  );
}

const ROW_STYLE = { gap: spacing.md, paddingHorizontal: spacing.base } as const;
