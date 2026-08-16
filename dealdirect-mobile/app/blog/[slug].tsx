import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { useBlogPost } from '@/features/content';
import { decodeHtmlEntities } from '@/lib';
import {
  EmptyState,
  ErrorState,
  Image,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
} from '@/ui';

/**
 * A blog post.
 *
 * ---------------------------------------------------------------------------
 * THE CONTENT IS HTML AND THIS RENDERS IT AS TEXT
 *
 * `Blog.content` comes out of the admin's rich-text editor, so it carries
 * markup. Rendering it faithfully needs either a WebView (a native module the
 * app deliberately does not have — HANDOFF §5.1 — and one that must never be
 * pointed at the DealDirect API anyway, see `api/client.ts`) or an HTML-to-RN
 * renderer, which is a dependency for one screen.
 *
 * So block tags become paragraph breaks, the rest are stripped, and entities
 * are decoded with the same helper chat and saved searches already use. What
 * is lost is inline emphasis, links and embedded images. What is kept is the
 * words, in the app's own type, with no new native surface. If the blog
 * becomes a real channel rather than an occasional post, this is the decision
 * to revisit first.
 */

/** Block-level tags whose boundaries are meaningful as paragraph breaks. */
const BLOCK_BREAK = /<\/(?:p|div|h[1-6]|li|blockquote|tr)>|<br\s*\/?>/gi;

function htmlToParagraphs(html: string): string[] {
  return decodeHtmlEntities(
    html
      .replace(/<(script|style)[\s\S]*?<\/\1>/gi, '')
      .replace(BLOCK_BREAK, '\n\n')
      .replace(/<[^>]+>/g, '')
  )
    .split(/\n{2,}/)
    .map((block) => block.replace(/[ \t]+/g, ' ').trim())
    .filter((block) => block.length > 0);
}

export default function BlogPostScreen() {
  const router = useRouter();
  const { slug } = useLocalSearchParams<{ slug: string }>();
  const { post, related, isLoading, error, refresh } = useBlogPost(slug);

  const paragraphs = useMemo(
    () => (post?.content ? htmlToParagraphs(post.content) : []),
    [post?.content]
  );

  return (
    <Screen edges={['top']}>
      {/* The post's own title carries the page; the header holds the category
          so the two do not say the same thing twice. */}
      <ScreenHeader title={post?.category ?? 'Blog'} backTo="/blog" />

      {isLoading ? (
        <View className="gap-base px-base pt-md">
          <Skeleton height={200} radius={12} />
          <Skeleton height={24} />
          <Skeleton height={120} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load this post" onRetry={refresh} />
      ) : !post ? (
        <EmptyState title="Post not found" />
      ) : (
        <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 48 }}>
          {post.coverImage ? (
            <Image
              uri={post.coverImage}
              size="full"
              style={{ width: '100%', height: 200, borderRadius: 12 }}
            />
          ) : null}

          <Text variant="title1" className="mt-base">
            {post.title}
          </Text>

          {post.publishedAt ? (
            <Text variant="footnote" tone="muted" className="mt-xs">
              {new Date(post.publishedAt).toLocaleDateString('en-IN', { dateStyle: 'long' })}
            </Text>
          ) : null}

          {paragraphs.length > 0 ? (
            paragraphs.map((paragraph, index) => (
              <Text key={index} variant="body" className="mt-base">
                {paragraph}
              </Text>
            ))
          ) : post.excerpt ? (
            <Text variant="body" className="mt-base">
              {post.excerpt}
            </Text>
          ) : null}

          {related.length > 0 ? (
            <View className="mt-2xl">
              <Text variant="title3" className="mb-base">
                Read next
              </Text>
              {related.map((item) => (
                <Pressable
                  key={item._id}
                  accessibilityRole="button"
                  accessibilityLabel={item.title}
                  onPress={() => router.push(`/blog/${item.slug}`)}
                  className="border-b border-border py-md active:opacity-70"
                >
                  <Text variant="body" numberOfLines={2}>
                    {item.title}
                  </Text>
                </Pressable>
              ))}
            </View>
          ) : null}
        </ScrollView>
      )}
    </Screen>
  );
}
