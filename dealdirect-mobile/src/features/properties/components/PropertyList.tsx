import { useRouter } from 'expo-router';
import React, { useCallback } from 'react';
import { ActivityIndicator, FlatList, RefreshControl, View, type ListRenderItemInfo } from 'react-native';

import { ApiError } from '@/api';
import { spacing, useTheme } from '@/theme';
import { EmptyState, ErrorState, Text } from '@/ui';
import type { PropertyFeed } from '../hooks';
import type { PropertySummary } from '../types';
import { PropertyCard } from './PropertyCard';
import { PropertyListSkeleton } from './PropertyCardSkeleton';

/**
 * The one property list, used by both the feed and the search results.
 *
 * It owns all four states — loading, empty, error, content — so neither screen
 * re-implements them and neither can forget one. A screen decides WHICH
 * properties; this decides how a list of them behaves.
 *
 * Still `FlatList` rather than `FlashList`: the migration is scoped to M12 and
 * `@shopify/flash-list` is not yet a dependency. `keyExtractor`, memoised rows
 * and a stable `onPress` are here already, so the swap is a one-line change to
 * the component name.
 */

export interface PropertyListProps {
  feed: PropertyFeed;
  /** Rendered above the first card and scrolls with the list. */
  header?: React.ReactElement;
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
const CONTENT_CONTAINER_STYLE = {
  // Cards carry no border or shadow, so the gap between them IS the separation.
  // At 16 they read as one continuous column; 24 is what makes each card a
  // distinct object without adding any chrome to do it.
  gap: spacing.xl,
  paddingHorizontal: spacing.base,
  paddingBottom: spacing['2xl'],
  // Lets the empty state centre itself. Without it the container collapses to
  // content height and "No matches" sits jammed under the header.
  flexGrow: 1,
} as const;

export function PropertyList({
  feed,
  header,
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
    ({ item }: ListRenderItemInfo<PropertySummary>) => (
      <PropertyCard property={item} onPress={openProperty} />
    ),
    [openProperty]
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
    <FlatList
      data={feed.items}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      ListHeaderComponent={header}
      contentContainerStyle={CONTENT_CONTAINER_STYLE}
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
        <ListFooter
          loading={feed.isLoadingMore}
          exhausted={!feed.hasMore && feed.items.length > 0}
          count={feed.items.length}
          total={feed.total}
        />
      }
      removeClippedSubviews
      initialNumToRender={4}
      maxToRenderPerBatch={6}
      windowSize={7}
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
