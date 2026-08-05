import { useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Alert, FlatList, Pressable, RefreshControl, View } from 'react-native';

import { INTEREST_LIMIT, useRemoveInterest, useSavedProperties } from '@/features/saved';
import {
  SavedSearchRow,
  useDeleteSavedSearch,
  useSavedSearches,
  useUpdateSavedSearchAlerts,
  type SavedSearchSummary,
} from '@/features/savedSearches';
import { PropertyCard, PropertyListSkeleton } from '@/features/properties';
import { useTheme } from '@/theme';
import { EmptyState, ErrorState, Screen, Text } from '@/ui';

/**
 * Saved.
 *
 * ---------------------------------------------------------------------------
 * THE FIRST TAB IS "INTERESTED", NOT "FAVOURITES", AND THAT IS NOT A WORD GAME
 *
 * `GET /properties/saved` reads the same `interestedUsers` array that
 * `POST /properties/interested/:id` writes. There is one list. Everything on
 * it was an announcement: the owner was emailed, a lead exists, and they hold
 * the user's name, email and phone.
 *
 * Calling that "Favourites" would be the single most misleading label in the
 * app — it implies private, free and unlimited, and it is none of those. The
 * heading says what it is, and the count line is functional rather than
 * decorative because the backend refuses a sixth listing anywhere in the app.
 * This screen is where a user comes to make room.
 *
 * The two segments are genuinely different objects — listings you acted on,
 * and standing alerts — so they are segments rather than one merged feed.
 */

type Segment = 'listings' | 'searches';

export default function SavedScreen() {
  const router = useRouter();
  const [segment, setSegment] = useState<Segment>('listings');

  return (
    <Screen>
      <View className="px-lg pt-md">
        <Text variant="title1">Saved</Text>

        <View className="mt-md flex-row rounded-xl bg-surface-muted p-xs">
          <SegmentButton
            label="Interested"
            active={segment === 'listings'}
            onPress={() => setSegment('listings')}
          />
          <SegmentButton
            label="Searches"
            active={segment === 'searches'}
            onPress={() => setSegment('searches')}
          />
        </View>
      </View>

      {segment === 'listings' ? (
        <InterestedList onOpenSearch={() => router.push('/(tabs)/search')} />
      ) : (
        <SearchesList />
      )}
    </Screen>
  );
}

function SegmentButton({
  label,
  active,
  onPress,
}: {
  label: string;
  active: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      accessibilityRole="tab"
      accessibilityState={{ selected: active }}
      onPress={onPress}
      className={`flex-1 items-center rounded-lg py-sm ${active ? 'bg-surface' : ''}`}
    >
      <Text variant={active ? 'bodyEmphasis' : 'body'} tone={active ? 'primary' : 'muted'}>
        {label}
      </Text>
    </Pressable>
  );
}

function InterestedList({ onOpenSearch }: { onOpenSearch: () => void }) {
  const router = useRouter();
  const theme = useTheme();
  const { items, isLoading, isRefreshing, error, refresh, used, remaining, requiresAuth } =
    useSavedProperties();
  const { remove } = useRemoveInterest();

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  const confirmRemove = useCallback(
    (id: string, title: string) => {
      // Confirmed because it frees a slot the user may be relying on, and
      // because the copy is the only place the lead's persistence is stated.
      Alert.alert(
        'Remove interest?',
        `You will be removed from the interested list for "${title}". The owner keeps the enquiry you already sent.`,
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Remove', style: 'destructive', onPress: () => remove(id) },
        ]
      );
    },
    [remove]
  );

  if (requiresAuth) {
    return (
      <EmptyState
        title="Sign in to see your list"
        description="Listings you show interest in appear here."
        actionLabel="Sign in"
        onAction={() => router.push('/(auth)/login')}
      />
    );
  }

  if (isLoading) return <PropertyListSkeleton />;

  if (error) return <ErrorState title="Could not load your list" onRetry={refresh} />;

  if (items.length === 0) {
    return (
      <EmptyState
        title="Nothing here yet"
        description="When you tell an owner you are interested, the listing appears here. You can have up to five at a time."
        actionLabel="Browse listings"
        onAction={onOpenSearch}
      />
    );
  }

  return (
    <FlatList
      data={items}
      keyExtractor={(item) => item.id}
      contentContainerStyle={{ paddingHorizontal: 24, paddingTop: 16, paddingBottom: 32, gap: 28 }}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={refresh}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      ListHeaderComponent={
        <Text variant="footnote" tone="muted">
          {used} of {INTEREST_LIMIT} used
          {remaining === 0
            ? '. Remove one to show interest in another listing.'
            : `. ${remaining} left.`}
        </Text>
      }
      renderItem={({ item }) => (
        <View>
          <PropertyCard property={item} onPress={openProperty} />
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Remove interest in ${item.title}`}
            onPress={() => confirmRemove(item.id, item.title)}
            hitSlop={8}
            className="mt-sm self-start"
            style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
          >
            <Text variant="footnote" tone="danger">
              Remove
            </Text>
          </Pressable>
        </View>
      )}
    />
  );
}

function SearchesList() {
  const router = useRouter();
  const theme = useTheme();
  const { items, isLoading, isRefreshing, error, refresh, requiresAuth } = useSavedSearches();
  const { setAlerts } = useUpdateSavedSearchAlerts();
  const { remove } = useDeleteSavedSearch();

  /**
   * Runs the search. Only the filters this app can express as search params
   * are carried: the price BAND is a saved-search concept with hard-coded
   * thresholds, and translating it into priceFrom/priceTo here would invent a
   * range the alert never used.
   */
  const run = useCallback(
    (search: SavedSearchSummary) => {
      router.push({
        pathname: '/(tabs)/search',
        params: search.city ? { city: search.city } : {},
      });
    },
    [router]
  );

  const confirmDelete = useCallback(
    (search: SavedSearchSummary) => {
      Alert.alert('Delete this search?', `"${search.name}" will stop alerting you.`, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Delete', style: 'destructive', onPress: () => remove(search.id) },
      ]);
    },
    [remove]
  );

  if (requiresAuth) {
    return (
      <EmptyState
        title="Sign in to save searches"
        description="Saved searches alert you when a new listing matches."
        actionLabel="Sign in"
        onAction={() => router.push('/(auth)/login')}
      />
    );
  }

  if (isLoading) return <PropertyListSkeleton />;

  if (error) return <ErrorState title="Could not load your searches" onRetry={refresh} />;

  if (items.length === 0) {
    return (
      <EmptyState
        title="No saved searches"
        description="Run a search, then save it to be alerted when new listings match."
        actionLabel="Search listings"
        onAction={() => router.push('/(tabs)/search')}
      />
    );
  }

  return (
    <FlatList
      data={items}
      keyExtractor={(item) => item.id}
      contentContainerStyle={{ paddingHorizontal: 24, paddingTop: 16, paddingBottom: 32, gap: 12 }}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={refresh}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      renderItem={({ item }) => (
        <SavedSearchRow
          search={item}
          onPress={run}
          onToggleAlerts={(id, notifyInApp) => setAlerts(id, { notifyInApp })}
          onDelete={confirmDelete}
        />
      )}
    />
  );
}
