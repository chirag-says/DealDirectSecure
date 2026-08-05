import { View } from 'react-native';

import { radius, spacing } from '@/theme';
import { Skeleton } from '@/ui';
import { COVER_HEIGHT } from './PropertyCard';

/**
 * Card-shaped placeholder.
 *
 * Mirrors `PropertyCard`'s geometry exactly: same cover height, same radius,
 * same gaps, and bar widths that stand in for the price, the location and the
 * spec line. A placeholder of the wrong shape still says "loading" but costs a
 * layout jump at the moment the user starts reading, which is the specific
 * failure skeletons exist to prevent.
 */
export function PropertyCardSkeleton() {
  return (
    <View>
      <Skeleton height={COVER_HEIGHT} radius={radius.lg} />
      <Skeleton width="42%" height={24} className="mt-md" />
      <Skeleton width="62%" height={18} className="mt-xs" />
      <Skeleton width="52%" height={14} className="mt-xs" />
    </View>
  );
}

export function PropertyListSkeleton({ count = 3 }: { count?: number }) {
  return (
    <View style={SKELETON_LIST_STYLE}>
      {Array.from({ length: count }, (_, index) => (
        <PropertyCardSkeleton key={index} />
      ))}
    </View>
  );
}

/** Matches the real list's row gap so the transition is seamless. */
const SKELETON_LIST_STYLE = {
  gap: spacing.xl,
  paddingHorizontal: spacing.base,
} as const;
