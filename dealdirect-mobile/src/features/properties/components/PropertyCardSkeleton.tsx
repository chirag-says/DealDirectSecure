import { View } from 'react-native';

import { spacing } from '@/theme';
import { Skeleton } from '@/ui';
import { CARD_RADIUS, COVER_ASPECT, ROW_RADIUS, THUMB_WIDTH_RATIO } from './cardParts';

/**
 * Card-shaped placeholders.
 *
 * They mirror the real geometry exactly — same aspect ratio, same radius, same
 * gaps, bar widths standing in for the price, location, spec row and
 * provenance line. A placeholder of the wrong shape still says "loading" and
 * still costs a layout jump at the moment the user starts reading, which is
 * the specific failure a skeleton exists to prevent.
 *
 * Both shapes are derived from `cardParts` rather than restated, so the pair
 * cannot drift the way the old fixed `COVER_HEIGHT` did once the card moved to
 * an aspect ratio.
 */
export function PropertyCardSkeleton() {
  return (
    <View className="overflow-hidden bg-surface" style={{ borderRadius: CARD_RADIUS }}>
      <Skeleton width="100%" style={{ aspectRatio: COVER_ASPECT }} radius={0} />
      <View style={{ padding: spacing.base }}>
        <Skeleton width="42%" height={24} />
        <Skeleton width="62%" height={18} className="mt-sm" />
        <Skeleton width="52%" height={14} className="mt-md" />
        <Skeleton width="38%" height={12} className="mt-md" />
      </View>
    </View>
  );
}

/** Matches `PropertyListItem`: photo column at a fixed share, three text lines. */
export function PropertyListItemSkeleton() {
  return (
    <View
      className="flex-row overflow-hidden bg-surface"
      style={{ borderRadius: ROW_RADIUS, alignItems: 'stretch' }}
    >
      <Skeleton width={`${THUMB_WIDTH_RATIO * 100}%`} style={{ aspectRatio: 1 }} radius={0} />
      <View style={{ flex: 1, padding: spacing.md, justifyContent: 'center' }}>
        <Skeleton width="46%" height={20} />
        <Skeleton width="70%" height={14} className="mt-xs" />
        <Skeleton width="56%" height={12} className="mt-sm" />
      </View>
    </View>
  );
}

export function PropertyListSkeleton({
  count = 3,
  density = 'card',
}: {
  count?: number;
  density?: 'card' | 'row';
}) {
  return (
    <View
      style={{
        // Same gaps the real list uses, so nothing shifts when data lands.
        gap: density === 'row' ? spacing.md : spacing.base,
        paddingHorizontal: spacing.base,
      }}
    >
      {Array.from({ length: count }, (_, index) =>
        density === 'row' ? (
          <PropertyListItemSkeleton key={index} />
        ) : (
          <PropertyCardSkeleton key={index} />
        )
      )}
    </View>
  );
}
