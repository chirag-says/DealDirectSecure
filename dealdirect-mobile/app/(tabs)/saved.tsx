import Ionicons from '@expo/vector-icons/Ionicons';
import { FlashList } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Alert, Pressable, RefreshControl, View } from 'react-native';

import { SignInPrompt } from '@/auth';
import { matchCity } from '@/features/home';
import { INTEREST_LIMIT, useRemoveInterest, useSavedProperties } from '@/features/saved';
import {
  SavedSearchRow,
  useDeleteSavedSearch,
  useSavedSearches,
  useUpdateSavedSearchAlerts,
  type SavedSearchSummary,
} from '@/features/savedSearches';
import { PropertyCard, PropertyListSkeleton } from '@/features/properties';
import { gesture, radius, screenPadding, spacing, tabBarClearance, useTheme } from '@/theme';
import {
  EmptyState,
  ErrorState,
  ProgressBar,
  Screen,
  ScreenHeader,
  Segmented,
  Skeleton,
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
    // `toast` is memoised by its provider (`ui/Toast.tsx`), so including it
    // does not make this callback unstable — it was omitted rather than being
    // deliberately excluded.
    [remove, toast]
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

/**
 * Mirrors `SavedSearchRow`'s geometry: a bordered card holding a name, the
 * composed filter description under it, and a footer row carrying the alert
 * switch and the delete control.
 *
 * Three of them, matching `PropertyListSkeleton`'s count, because that is what
 * every other list in the app shows while loading and a different number reads
 * as a different kind of wait.
 */
function SavedSearchListSkeleton() {
  return (
    <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
      {[0, 1, 2].map((index) => (
        <View key={index} className="rounded-xl border border-border bg-surface p-md">
          <Skeleton width="52%" height={18} />
          <Skeleton width="74%" height={14} className="mt-sm" />
          <View className="mt-md flex-row items-center justify-between">
            <Skeleton width={92} height={14} />
            <Skeleton width={44} height={24} radius={radius.full} />
          </View>
        </View>
      ))}
    </View>
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
   * Runs the search.
   *
   * ---------------------------------------------------------------------------
   * THIS DID NOTHING UNTIL 2026-08-14
   *
   * It pushed `{ city: search.city }` — a param the results screen has never
   * read. That screen ignores unknown params AND returns early from its route
   * effect when none of the ones it knows are present, so tapping a saved
   * search switched to the Properties tab and left whatever was already there.
   * Silent, because switching tabs looks like something happening.
   *
   * ---------------------------------------------------------------------------
   * WHY THE CITY IS TRANSLATED RATHER THAN PASSED THROUGH
   *
   * A saved search stores the city as the STRING the user picked ("Bangalore"),
   * because that is what the backend's alert matcher compares against. The
   * results screen's city filter is keyed by `City.id`, which merges the
   * spellings that string cannot — `address.city` holds both "Bangalore" and
   * "Bengaluru" in production today. `matchCity` is the bridge.
   *
   * A city we have no entry for falls back to free text, which the `search`
   * regex covers against `address.city` and `address.area`. Narrower than the
   * alias-matched filter, and much better than dropping the only criterion the
   * search had.
   *
   * ---------------------------------------------------------------------------
   * THE PRICE BAND IS STILL NOT CARRIED, AND THAT IS STILL DELIBERATE
   *
   * A saved search's band is one of three fixed buckets the alert matcher
   * understands — under ₹50 Lakh, ₹50 Lakh to ₹1.5 Crore, above ₹1.5 Crore —
   * and none of them line up with the five the results screen filters by. The
   * nearest fit would silently run a different search from the one the alert
   * is watching, which is worse than running a wider one: the user would draw
   * conclusions about their alert from results it was never going to send.
   *
   * Running wide is honest and recoverable — the budget pill is right there on
   * the rail. Running subtly-wrong is neither.
   */
  const run = useCallback(
    (search: SavedSearchSummary) => {
      const params: Record<string, string> = {};

      const city = matchCity(search.city);
      if (city) params.city = city.id;
      else if (search.city) params.search = search.city;

      // Only "rent" survives the round trip. `availableFor` is compared to a
      // `listingType` that has three spellings of for-sale in the schema, so a
      // saved "sale" search is one the matcher mostly misses anyway — see the
      // field notes at the top of `savedSearches/types.ts`.
      if (search.availableFor === 'rent') params.listingType = 'rent';

      // Nothing expressible at all still has to produce a results screen
      // rather than a no-op, so it browses everything.
      if (Object.keys(params).length === 0) params.browse = '1';

      router.push({ pathname: '/(tabs)/properties', params });
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
    [remove, toast]
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

  // NOT `PropertyListSkeleton`. This tab renders text rows about 90pt tall, and
  // standing in for them with three 300pt property cards makes the whole list
  // collapse upward the moment the data lands — a skeleton of the wrong shape
  // announces loading and then causes the exact jump it exists to prevent.
  if (isLoading) return <SavedSearchListSkeleton />;

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
