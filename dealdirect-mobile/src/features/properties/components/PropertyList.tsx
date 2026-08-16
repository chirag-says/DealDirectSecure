import { FlashList, type ListRenderItemInfo } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import React, { useCallback } from 'react';
import { ActivityIndicator, RefreshControl, View } from 'react-native';

import { ApiError } from '@/api';
import { spacing, tabBarClearance, useTheme } from '@/theme';
import { EmptyState, ErrorState, Text } from '@/ui';
import type { PropertyFeed } from '../hooks';
import type { PropertySummary } from '../types';
import { PropertyCard, type CompareControlProps, type SaveControlProps } from './PropertyCard';
import { PropertyListItem } from './PropertyListItem';
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
  /**
   * The save control, per item. Undefined renders no heart — the owner's own
   * listings screen is the only surface where saving makes no sense.
   */
  getSaveProps?: (item: PropertySummary) => SaveControlProps;
  /**
   * Compare selection, per item. Present only while the results toolbar's
   * Compare mode is on, and it takes the save control's corner while it is —
   * one corner, one action. See `cardParts`.
   */
  getCompareProps?: (item: PropertySummary) => CompareControlProps;
  /**
   * `card` is the full-width photo; `row` is the compact horizontal shape.
   * The Properties screen exposes this as a toggle — see `PropertyListItem`
   * for why both exist rather than one being simply better.
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
  paddingHorizontal: spacing.base,
  paddingBottom: tabBarClearance,
  // Lets the empty state centre itself. Without it the container collapses to
  // content height and "No matches" sits jammed under the header.
  flexGrow: 1,
} as const;

const ROW_CONTENT_STYLE = {
  paddingHorizontal: spacing.base,
  paddingBottom: tabBarClearance,
  flexGrow: 1,
} as const;

/**
 * THE GAP IS A SEPARATOR, NOT `gap` — corrected 2026-08-15.
 *
 * The container carried `gap: 16` and the cards still touched on device. The
 * reason is structural rather than a wrong value: FlashList v2 positions every
 * cell ABSOLUTELY inside its content container (its own `CellRendererComponent`
 * documentation states `position` "will be `absolute` as that's how `FlashList`
 * positions elements"). Flex `gap` has no effect on absolutely positioned
 * children, so the property was inert. `paddingHorizontal` and `paddingBottom`
 * on the same object DO work, which is what made the bug look like a spacing
 * value that was simply too small.
 *
 * `ItemSeparatorComponent` is the supported mechanism and it is measured into
 * the layout, so virtualisation and scroll offsets stay correct. It renders
 * BETWEEN items only — never above the first or below the last — which is
 * exactly the requirement, and it means no card needs a margin of its own.
 *
 * Module-level and separately declared per density so the reference is stable
 * across renders; an inline arrow here would remount every separator on every
 * parent render.
 *
 * 16 between cards, 12 between rows. Compact rows want the tighter gap for the
 * same reason they exist — they should read as one column, and a card-sized
 * gap scatters them into unrelated fragments.
 */
const CardSeparator = () => <View style={{ height: spacing.base }} />;
const RowSeparator = () => <View style={{ height: spacing.md }} />;

export function PropertyList({
  feed,
  header,
  footer,
  getSaveProps,
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
        <PropertyListItem property={item} onPress={openProperty} save={getSaveProps?.(item)} />
      ) : (
        <PropertyCard
          property={item}
          onPress={openProperty}
          save={getSaveProps?.(item)}
          compare={getCompareProps?.(item)}
        />
      ),
    [openProperty, getSaveProps, getCompareProps, density]
  );

  // First load with nothing on screen. Once there is content, a refresh or a
  // next-page fetch must never replace it with a placeholder.
  if (feed.isInitialLoading) {
    return (
      <View className="flex-1 pt-base">
        <HeaderSlot>{header}</HeaderSlot>
        <PropertyListSkeleton density={density} />
      </View>
    );
  }

  if (feed.error && feed.items.length === 0) {
    const error = feed.error instanceof ApiError ? feed.error : undefined;
    const rateLimited = error?.kind === 'rateLimited';

    return (
      <View className="flex-1">
        <HeaderSlot>{header}</HeaderSlot>
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
      // `ItemSeparatorComponent` runs between ITEMS only, so the header gets
      // its own matching gap rather than sitting flush on the first card.
      ListHeaderComponent={header}
      ListHeaderComponentStyle={{
        marginBottom: density === 'row' ? spacing.md : spacing.base,
      }}
      contentContainerStyle={density === 'row' ? ROW_CONTENT_STYLE : CARD_CONTENT_STYLE}
      ItemSeparatorComponent={density === 'row' ? RowSeparator : CardSeparator}
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

/**
 * Gives the header the same horizontal inset it gets inside the list.
 *
 * In the content branch the header sits inside `contentContainerStyle` and
 * picks up its `paddingHorizontal` for free. The loading and error branches are
 * plain views, so without this the header jumps to the screen edge for exactly
 * as long as the fetch takes and then jumps back — which, since the header is
 * now a result count and two controls rather than nothing, is a visible
 * sideways shift at the moment the data lands.
 *
 * Renders nothing at all when there is no header, rather than an empty padded
 * view that would add a gap above the skeleton.
 */
function HeaderSlot({ children }: { children?: React.ReactElement }) {
  if (!children) return null;
  return <View style={{ paddingHorizontal: spacing.base }}>{children}</View>;
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
