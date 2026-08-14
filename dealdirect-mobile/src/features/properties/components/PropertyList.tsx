import { FlashList, type ListRenderItemInfo } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import React, { useCallback } from 'react';
import { ActivityIndicator, RefreshControl, View } from 'react-native';

import { ApiError } from '@/api';
import { spacing, tabBarClearance, useTheme } from '@/theme';
import { EmptyState, ErrorState, Text } from '@/ui';
import type { PropertyFeed } from '../hooks';
import type { PropertySummary } from '../types';
import { PropertyCard, PropertyRow, type PropertyCompareProps } from './PropertyCard';
import { PropertyListSkeleton } from './PropertyCardSkeleton';

/**
 * The one property list, used by both the feed and the search results.
 *
 * It owns all four states — loading, empty, error, content — so neither screen
 * re-implements them and neither can forget one. A screen decides WHICH
 * properties; this decides how a list of them behaves.
 *
 * `FlashList` (M12) rather than `FlatList` — this list is the single longest
 * scroll in the app (search results, unbounded) and the one virtualization
 * mattered most for. FlashList v2 (New Architecture only, which this app runs)
 * auto-sizes rows, so the old `initialNumToRender`/`maxToRenderPerBatch`/
 * `windowSize`/`removeClippedSubviews` tuning FlatList needed is gone rather
 * than carried over as dead props.
 */

export interface PropertyListProps {
  feed: PropertyFeed;
  /** Rendered above the first card and scrolls with the list. */
  header?: React.ReactElement;
  /** Rendered below the pagination footer, e.g. a "Related properties" rail
   *  when the list itself came up short. Scrolls with the list. */
  footer?: React.ReactElement;
  /** When present, every card renders a compare-selection chip built from
   *  this. Undefined (the default) renders no chip — every screen other than
   *  search results leaves this unset. */
  getCompareProps?: (item: PropertySummary) => PropertyCompareProps;
  /**
   * `card` is the full-width photo; `row` is the compact horizontal shape.
   * The Properties screen exposes this as a toggle — see `PropertyRow` for
   * why both exist rather than one being simply better.
   */
  density?: 'card' | 'row';
  emptyTitle?: string;
  emptyDescription?: string;
  emptyActionLabel?: string;
  onEmptyAction?: () => void;
}

const keyExtractor = (item: PropertySummary) => item.id;

/**
 * Module-level so the reference is stable. An inline object here would be a new
 * prop on every render of the parent, which defeats FlatList's own bail-outs.
 */
/**
 * Two spacings, because the two densities need different ones.
 *
 * A full card is a large object and needs a real gap to read as separate from
 * the next one. A compact row is small enough that the same gap would scatter
 * the list into unrelated fragments — rows want to read as a column.
 *
 * `paddingBottom` clears the floating dock (`tabBarClearance`); the list would
 * otherwise end with its last card behind the pill.
 */
const CARD_CONTENT_STYLE = {
  gap: spacing.base,
  paddingHorizontal: spacing.base,
  paddingBottom: tabBarClearance,
  // Lets the empty state centre itself. Without it the container collapses to
  // content height and "No matches" sits jammed under the header.
  flexGrow: 1,
} as const;

const ROW_CONTENT_STYLE = {
  gap: spacing.md,
  paddingHorizontal: spacing.base,
  paddingBottom: tabBarClearance,
  flexGrow: 1,
} as const;

export function PropertyList({
  feed,
  header,
  footer,
  getCompareProps,
  density = 'card',
  emptyTitle = 'No properties yet',
  emptyDescription = 'Nothing matches this view right now.',
  emptyActionLabel,
  onEmptyAction,
}: PropertyListProps) {
  const router = useRouter();
  const theme = useTheme();

  const openProperty = useCallback(
    (id: string) => router.push(`/property/${id}`),
    [router]
  );

  const renderItem = useCallback(
    ({ item }: ListRenderItemInfo<PropertySummary>) =>
      density === 'row' ? (
        <PropertyRow property={item} onPress={openProperty} />
      ) : (
        <PropertyCard
          property={item}
          onPress={openProperty}
          compare={getCompareProps?.(item)}
        />
      ),
    [openProperty, getCompareProps, density]
  );

  // First load with nothing on screen. Once there is content, a refresh or a
  // next-page fetch must never replace it with a placeholder.
  if (feed.isInitialLoading) {
    return (
      <View className="flex-1 pt-base">
        {header}
        <PropertyListSkeleton />
      </View>
    );
  }

  if (feed.error && feed.items.length === 0) {
    const error = feed.error instanceof ApiError ? feed.error : undefined;
    const rateLimited = error?.kind === 'rateLimited';

    return (
      <View className="flex-1">
        {header}
        <ErrorState
          title={rateLimited ? 'Too many searches' : 'Could not load properties'}
          description={
            rateLimited
              ? waitMessage(error?.retryAfterSeconds)
              : (error?.message ?? 'Please check your connection and try again.')
          }
          requestId={error?.requestId}
          onRetry={feed.retry}
        />
      </View>
    );
  }

  return (
    <FlashList
      data={feed.items}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      ListHeaderComponent={header}
      contentContainerStyle={density === 'row' ? ROW_CONTENT_STYLE : CARD_CONTENT_STYLE}
      keyboardShouldPersistTaps="handled"
      keyboardDismissMode="on-drag"
      refreshControl={
        <RefreshControl
          refreshing={feed.isRefreshing}
          onRefresh={feed.refresh}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      onEndReached={feed.loadMore}
      // Half a screen of runway. Firing at the very bottom shows the user a
      // spinner they have to wait through; firing much earlier spends pages
      // they may never scroll to, against a shared rate limit.
      onEndReachedThreshold={0.5}
      ListEmptyComponent={
        <EmptyState
          title={emptyTitle}
          description={emptyDescription}
          actionLabel={emptyActionLabel}
          onAction={onEmptyAction}
        />
      }
      ListFooterComponent={
        <>
          <ListFooter
            loading={feed.isLoadingMore}
            exhausted={!feed.hasMore && feed.items.length > 0}
            count={feed.items.length}
            total={feed.total}
          />
          {footer}
        </>
      }
    />
  );
}

function waitMessage(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) return 'Please wait a moment and try again.';
  if (seconds < 60) return `Please wait about ${Math.ceil(seconds)} seconds and try again.`;
  return `Please wait about ${Math.ceil(seconds / 60)} minutes and try again.`;
}

function ListFooter({
  loading,
  exhausted,
  count,
  total,
}: {
  loading: boolean;
  exhausted: boolean;
  count: number;
  total: number;
}) {
  if (loading) {
    return (
      <View className="items-center py-lg">
        <ActivityIndicator />
      </View>
    );
  }

  if (!exhausted) return null;

  return (
    <View className="items-center py-lg">
      <Text variant="footnote" tone="muted">
        {count === total
          ? `All ${total.toLocaleString('en-IN')} results shown`
          : `Showing ${count.toLocaleString('en-IN')} of ${total.toLocaleString('en-IN')}`}
      </Text>
    </View>
  );
}
