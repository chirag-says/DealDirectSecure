import Ionicons from '@expo/vector-icons/Ionicons';
import { FlashList } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Alert, Pressable, RefreshControl, View } from 'react-native';

import { SignInPrompt } from '@/auth';
import { INTEREST_LIMIT, useRemoveInterest, useSavedProperties } from '@/features/saved';
import {
  SavedSearchRow,
  useDeleteSavedSearch,
  useSavedSearches,
  useUpdateSavedSearchAlerts,
  type SavedSearchSummary,
} from '@/features/savedSearches';
import { PropertyCard, PropertyListSkeleton } from '@/features/properties';
import { gesture, screenPadding, spacing, tabBarClearance, useTheme } from '@/theme';
import {
  EmptyState,
  ErrorState,
  ProgressBar,
  Screen,
  ScreenHeader,
  Segmented,
  Text,
  useToast,
} from '@/ui';

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
    <Screen edges={['top']}>
      {/* A root tab has nowhere to go back TO, so no back affordance. */}
      <ScreenHeader title="Saved" showBack={false} tight />

      <View style={{ paddingHorizontal: screenPadding, paddingVertical: spacing.md }}>
        <Segmented options={SEGMENTS} value={segment} onChange={setSegment} />
      </View>

      {segment === 'listings' ? (
        <InterestedList onOpenSearch={() => router.push('/(tabs)/properties')} />
      ) : (
        <SearchesList />
      )}
    </Screen>
  );
}

const SEGMENTS = [
  // "Interested", not "Favourites": adding to this list emails the owner and
  // creates a lead. See `features/properties/interest.ts`.
  { label: 'Interested', value: 'listings' as const },
  { label: 'Searches', value: 'searches' as const },
];

function InterestedList({ onOpenSearch }: { onOpenSearch: () => void }) {
  const router = useRouter();
  const theme = useTheme();
  const { items, isLoading, isRefreshing, error, refresh, used, remaining, requiresAuth } =
    useSavedProperties();
  const { remove } = useRemoveInterest();
  const toast = useToast();

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
          {
            text: 'Remove',
            style: 'destructive',
            onPress: async () => {
              await remove(id);
              toast.show('Removed from your interested list.');
            },
          },
        ]
      );
    },
    [remove]
  );

  if (requiresAuth) {
    return (
      <SignInPrompt
        icon="heart-outline"
        title="Your interested list"
        description="Listings you tell an owner you are interested in appear here."
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
    <FlashList
      data={items}
      keyExtractor={(item) => item.id}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
        gap: spacing.base,
      }}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={refresh}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      /*
        THE CAP IS THE HEADER, AND IT IS A METER RATHER THAN A SENTENCE.

        The backend refuses a sixth interest anywhere in the app, so this
        screen is where a user comes to make room. A line of grey text saying
        "3 of 5 used" states that; a filled bar shows it, and shows how close
        to the wall they are without them having to do the subtraction.

        It turns danger-toned at the cap, because at that point it has stopped
        being information and started being the reason their next tap will
        fail.
      */
      ListHeaderComponent={
        <View className="mb-xs">
          <View className="mb-sm flex-row items-baseline justify-between">
            <Text variant="footnote" tone="secondary">
              {used} of {INTEREST_LIMIT} enquiries used
            </Text>
            <Text variant="caption" tone={remaining === 0 ? 'danger' : 'muted'}>
              {remaining === 0 ? 'Limit reached' : `${remaining} left`}
            </Text>
          </View>
          <ProgressBar
            value={used / INTEREST_LIMIT}
            tone={remaining === 0 ? 'brand' : 'accent'}
            size="sm"
            label={`${used} of ${INTEREST_LIMIT} enquiries used`}
          />
          {remaining === 0 ? (
            <Text variant="caption" tone="muted" className="mt-sm">
              Remove one below to show interest in another listing.
            </Text>
          ) : null}
        </View>
      }
      renderItem={({ item }) => (
        <View>
          <PropertyCard property={item} onPress={openProperty} />

          {/*
            The remove control sits UNDER the card rather than on it. Putting
            it over the photo would make it compete with the card's own press
            target for the same pixels, and this is a destructive action on a
            list capped at five — it should take a deliberate second look, not
            a thumb brushing past the corner of an image.
          */}
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Remove interest in ${item.title}`}
            onPress={() => confirmRemove(item.id, item.title)}
            hitSlop={gesture.hitSlop}
            className="mt-sm flex-row items-center self-start"
            style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
          >
            <Ionicons name="close-circle-outline" size={15} color={theme.colors.danger} />
            <Text variant="footnote" tone="danger" className="ml-xs">
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
  const toast = useToast();

  /**
   * Runs the search. Only the filters this app can express as search params
   * are carried: the price BAND is a saved-search concept with hard-coded
   * thresholds, and translating it into priceFrom/priceTo here would invent a
   * range the alert never used.
   */
  const run = useCallback(
    (search: SavedSearchSummary) => {
      router.push({
        pathname: '/(tabs)/properties',
        params: search.city ? { city: search.city } : {},
      });
    },
    [router]
  );

  const confirmDelete = useCallback(
    (search: SavedSearchSummary) => {
      Alert.alert('Delete this search?', `"${search.name}" will stop alerting you.`, [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            await remove(search.id);
            toast.show('Saved search deleted.');
          },
        },
      ]);
    },
    [remove]
  );

  if (requiresAuth) {
    return (
      <SignInPrompt
        icon="bookmark-outline"
        title="Your saved searches"
        description="Save a search and we will alert you when a new listing matches it."
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
        onAction={() => router.push('/(tabs)/properties')}
      />
    );
  }

  return (
    <FlashList
      data={items}
      keyExtractor={(item) => item.id}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
        gap: spacing.md,
      }}
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
