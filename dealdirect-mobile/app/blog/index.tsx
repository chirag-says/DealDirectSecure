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
 * ---------------------------------------------------------------------------
 * REACHABLE BY DEEP LINK ONLY — 2026-08-24
 *
 * Nothing in the app navigates here any more. The row that did was in
 * Profile's link directory, and it went when that directory did.
 *
 * The reasoning is the division of labour between the two products: the
 * website exists to explain DealDirect and to be found, and its articles are
 * SEO surface — they earn their keep by ranking, which an app cannot do. An
 * app's job is to help someone search, shortlist, enquire and manage, and a
 * content channel competes with that for the one thing a phone screen does not
 * have, which is room. Every competitor keeps its articles on the web for the
 * same reason.
 *
 * The routes stay on disk rather than being deleted, because `dealdirect://`
 * covers the whole route tree and a post shared from the website should open
 * rather than 404. That also means the screens must keep working: this one is
 * unchanged, and `[slug]` still renders through its HTML stripper, which is a
 * known limitation recorded as W12 rather than a regression introduced here.
 *
 * Whether to delete these two routes outright is a product decision, not an
 * engineering one, and it is open.
 *
 * ---------------------------------------------------------------------------
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
      <ScreenHeader title="Blog" backTo="/(tabs)" />

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
