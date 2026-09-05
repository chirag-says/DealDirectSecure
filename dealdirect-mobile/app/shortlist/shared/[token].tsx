import Ionicons from '@expo/vector-icons/Ionicons';
import { FlashList } from '@shopify/flash-list';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback } from 'react';
import { View } from 'react-native';

import { ShortlistRow, useSharedShortlist } from '@/features/shortlist';
import { radius, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import { EmptyState, ErrorState, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * Somebody else's shortlist, opened from a link.
 *
 * ---------------------------------------------------------------------------
 * PUBLIC, AND READ-ONLY BY CONSTRUCTION
 *
 * No session is required and none is used: `GET /shortlist/shared/:token` is a
 * public route, and the screen renders `ShortlistRow` without passing any of
 * the control props, so there is no save, no note, no remove and no selection
 * to accidentally leave enabled. The read-only-ness is structural rather than
 * a flag somebody has to remember to set.
 *
 * A visitor can still tap through to a listing, which is the point of being
 * sent the link, and the detail screen offers them their own Save exactly as
 * it would from anywhere else.
 *
 * ---------------------------------------------------------------------------
 * A DEAD LINK IS AN EMPTY STATE, NOT AN ERROR
 *
 * Expired, revoked and never-existed all come back as 404, and from here they
 * are the same fact: there is nothing at this address any more. Saying "could
 * not load" would suggest retrying, which cannot help. The way forward offered
 * is the app's own search, because a person who was sent a shortlist is
 * someone who is looking for a home.
 *
 * ---------------------------------------------------------------------------
 * DEEP LINK SAFETY
 *
 * This route can be a cold start (`dealdirect://shortlist/shared/<token>`), so
 * it raises no sheet, no confirmation and no payment of any kind — it draws a
 * list and stops. `ScreenHeader` is given an explicit `backTo` because a cold
 * start has no history to pop.
 */
export default function SharedShortlistScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { token } = useLocalSearchParams<{ token: string }>();
  const { shortlist, isLoading, isMissing, error, refresh } = useSharedShortlist(token);

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  const expires = shortlist?.expiresAt ? formatExpiry(shortlist.expiresAt) : null;

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="Shared shortlist" backTo="/(tabs)" />

      {isLoading ? (
        <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
          <Skeleton width="60%" height={20} />
          {[0, 1, 2].map((index) => (
            <Skeleton key={index} height={94} radius={radius.lg} />
          ))}
        </View>
      ) : isMissing ? (
        <EmptyState
          icon={
            <View
              className="items-center justify-center rounded-full"
              style={{ width: 72, height: 72, backgroundColor: theme.colors.surfaceMuted }}
            >
              <Ionicons name="link-outline" size={30} color={theme.colors.textMuted} />
            </View>
          }
          title="This link is no longer live"
          description="Whoever shared it has replaced or revoked it, or it has expired. Ask them for a new one."
          actionLabel="Search listings"
          onAction={() => router.push('/(tabs)/search')}
        />
      ) : error ? (
        <ErrorState title="Could not open this shortlist" onRetry={refresh} />
      ) : !shortlist || shortlist.items.length === 0 ? (
        <EmptyState
          title="Nothing on this shortlist"
          description="The list behind this link is empty right now."
          actionLabel="Search listings"
          onAction={() => router.push('/(tabs)/search')}
        />
      ) : (
        <FlashList
          data={shortlist.items}
          keyExtractor={(item) => item.property.id}
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
          ItemSeparatorComponent={Separator}
          ListHeaderComponentStyle={{ marginBottom: spacing.base }}
          ListHeaderComponent={
            <View>
              <Text variant="title3">
                {shortlist.label
                  ? `This is ${shortlist.label}'s shortlist`
                  : 'A shared shortlist'}
              </Text>
              <Text variant="footnote" tone="secondary" className="mt-xs">
                {shortlist.items.length}{' '}
                {shortlist.items.length === 1 ? 'listing' : 'listings'}
                {expires ? ` · link works until ${expires}` : ''}
              </Text>
            </View>
          }
          ListFooterComponent={
            <Text variant="caption" tone="muted" className="mt-lg text-center">
              You are looking at someone else&apos;s saved listings. Nothing you do here changes
              their list.
            </Text>
          }
          renderItem={({ item }) => <ShortlistRow entry={item} onPress={openProperty} />}
        />
      )}
    </Screen>
  );
}

const Separator = () => <View style={{ height: spacing.md }} />;

/** "12 October". An invalid date renders nothing rather than "Invalid Date". */
function formatExpiry(value: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-IN', { day: 'numeric', month: 'long' });
}
