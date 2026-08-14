import { FlashList, type ListRenderItemInfo } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import React, { useCallback } from 'react';
import { ActivityIndicator, RefreshControl, View } from 'react-native';

import { ApiError } from '@/api';
import { spacing, useTheme } from '@/theme';
import { EmptyState, ErrorState, Skeleton, Text } from '@/ui';
import type { ProjectFeed } from '../hooks';
import type { ProjectSummary } from '../types';
import { ProjectListCard } from './ProjectListCard';

/** Mirrors `PropertyList` — same four states, same list-vs-search reuse. */
export interface ProjectListProps {
  feed: ProjectFeed;
  header?: React.ReactElement;
}

const keyExtractor = (item: ProjectSummary) => item.id;

const CONTENT_CONTAINER_STYLE = {
  gap: spacing.xl,
  paddingHorizontal: spacing.base,
  paddingBottom: spacing['2xl'],
  flexGrow: 1,
} as const;

export function ProjectList({ feed, header }: ProjectListProps) {
  const router = useRouter();
  const theme = useTheme();

  const openProject = useCallback((id: string) => router.push(`/projects/${id}`), [router]);

  const renderItem = useCallback(
    ({ item }: ListRenderItemInfo<ProjectSummary>) => <ProjectListCard project={item} onPress={openProject} />,
    [openProject]
  );

  if (feed.isInitialLoading) {
    return (
      <View className="flex-1 px-base pt-base">
        {header}
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} height={260} radius={16} className="mb-xl" />
        ))}
      </View>
    );
  }

  if (feed.error && feed.items.length === 0) {
    const error = feed.error instanceof ApiError ? feed.error : undefined;
    return (
      <View className="flex-1">
        {header}
        <ErrorState
          title="Could not load projects"
          description={error?.message}
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
      contentContainerStyle={CONTENT_CONTAINER_STYLE}
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
      onEndReachedThreshold={0.5}
      ListEmptyComponent={<EmptyState title="No projects yet" description="Check back soon." />}
      ListFooterComponent={
        feed.isLoadingMore ? (
          <View className="items-center py-lg">
            <ActivityIndicator />
          </View>
        ) : !feed.hasMore && feed.items.length > 0 ? (
          <View className="items-center py-lg">
            <Text variant="footnote" tone="muted">
              {feed.items.length === feed.total
                ? `All ${feed.total.toLocaleString('en-IN')} projects shown`
                : `Showing ${feed.items.length.toLocaleString('en-IN')} of ${feed.total.toLocaleString('en-IN')}`}
            </Text>
          </View>
        ) : null
      }
    />
  );
}
