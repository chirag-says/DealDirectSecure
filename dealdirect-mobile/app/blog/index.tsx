import { FlashList } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import { Pressable, RefreshControl, View } from 'react-native';

import { useBlogFeed } from '@/features/content';
import { useTheme } from '@/theme';
import type { Blog } from '@/types/backend/misc';
import { EmptyState, ErrorState, Image, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * Blog list.
 *
 * `FlashList` because this is unbounded and paginated, matching the choice
 * made for search results, leads and notifications. Posts are addressed by
 * SLUG downstream, not by id — see `features/content/blog.ts`.
 */
export default function BlogListScreen() {
  const router = useRouter();
  const theme = useTheme();
  const feed = useBlogFeed();

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="Blog" backTo="/(tabs)/profile" />

      {feed.isLoading ? (
        <View className="gap-base px-base pt-md">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} height={104} radius={12} />
          ))}
        </View>
      ) : feed.error ? (
        <ErrorState title="Could not load the blog" onRetry={feed.refresh} />
      ) : feed.posts.length === 0 ? (
        <EmptyState title="Nothing published yet" description="Check back soon." />
      ) : (
        <FlashList
          data={feed.posts}
          keyExtractor={(post) => post._id}
          contentContainerStyle={{ padding: 16 }}
          renderItem={({ item }) => (
            <PostRow post={item} onPress={() => router.push(`/blog/${item.slug}`)} />
          )}
          onEndReachedThreshold={0.6}
          onEndReached={feed.loadMore}
          refreshControl={
            <RefreshControl
              refreshing={feed.isRefreshing}
              onRefresh={feed.refresh}
              tintColor={theme.colors.brand}
            />
          }
          ListFooterComponent={
            feed.isLoadingMore ? <Skeleton height={104} radius={12} /> : null
          }
        />
      )}
    </Screen>
  );
}

function PostRow({ post, onPress }: { post: Blog; onPress: () => void }) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={post.title}
      onPress={onPress}
      className="mb-base flex-row active:opacity-75"
    >
      {post.coverImage ? (
        <Image
          uri={post.coverImage}
          size="thumb"
          style={{ width: 96, height: 96, borderRadius: 12 }}
        />
      ) : null}

      <View className={post.coverImage ? 'ml-base flex-1' : 'flex-1'}>
        {post.category ? (
          <Text variant="caption" tone="accent" className="mb-xs">
            {post.category}
          </Text>
        ) : null}
        <Text variant="bodyEmphasis" numberOfLines={2}>
          {post.title}
        </Text>
        {post.excerpt ? (
          <Text variant="footnote" tone="secondary" numberOfLines={2} className="mt-xs">
            {post.excerpt}
          </Text>
        ) : null}
        {post.publishedAt ? (
          <Text variant="caption" tone="muted" className="mt-xs">
            {new Date(post.publishedAt).toLocaleDateString('en-IN', { dateStyle: 'medium' })}
          </Text>
        ) : null}
      </View>
    </Pressable>
  );
}
