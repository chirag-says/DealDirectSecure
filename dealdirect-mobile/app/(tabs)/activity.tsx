import Ionicons from '@expo/vector-icons/Ionicons';
import { FlashList } from '@shopify/flash-list';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Alert, Pressable, RefreshControl, ScrollView, View } from 'react-native';

import { SignInPrompt } from '@/auth';
import { matchCity } from '@/features/home';
import {
  EnquiryMeter,
  EnquirySheet,
  useSaveToggle,
  useSavedProperties,
  type SaveToggle,
} from '@/features/saved';
import {
  SavedSearchRow,
  useDeleteSavedSearch,
  useSavedSearches,
  useUpdateSavedSearchAlerts,
  type SavedSearchSummary,
} from '@/features/savedSearches';
import {
  PropertyListSkeleton,
  PropertyRail,
  SavedPropertyCard,
  clearRecentlyViewed,
  useRecentlyViewed,
} from '@/features/properties';
import { BookingRow, useMyBookings } from '@/features/projects';
import { ShortlistRow, removeFromShortlist, useShortlist } from '@/features/shortlist';
import { gesture, radius, screenPadding, spacing, tabBarClearance, useTheme } from '@/theme';
import {
  EmptyState,
  ErrorState,
  Screen,
  ScreenHeader,
  SectionLabel,
  Segmented,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * Activity — everything the user has in flight.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT "SAVED" ANY MORE — 2026-08-24
 *
 * It used to hold one list and one set of alerts, which described a storage
 * bucket rather than a person's situation. Somebody looking for a home has
 * four things going at once: the flats they are turning over, the owners they
 * have written to, the searches they are watching, and the units they have put
 * money or a name against. Those were spread across a tab, a profile link and a
 * deep-linked screen, so nowhere in the app answered "where am I up to".
 *
 * Four segments now, in the order the user moves through them:
 *
 *   Shortlist   considering       device-local, free, unlimited
 *   Enquiries   contacted         server, capped at 5, owner notified
 *   Searches    watching          server, alerting
 *   Bookings    committed         server, money or a callback
 *
 * ---------------------------------------------------------------------------
 * SHORTLIST AND ENQUIRIES ARE TWO LISTS, AND THE SPLIT IS THE WHOLE POINT
 *
 * `GET /properties/saved` reads the same `interestedUsers` array that
 * `POST /properties/interested/:id` writes. There is one server list, and
 * everything on it was an announcement: the owner was emailed and messaged on
 * WhatsApp, a lead exists, and they hold the user's name, email and phone.
 * It is capped at five.
 *
 * Calling that "Favourites" would be the single most misleading label in the
 * app — it implies private, free and unlimited, and it is none of those. So it
 * is called Enquiries, which is what it is, and the count line stays because
 * the backend refuses a sixth anywhere in the app and this is where a user
 * comes to make room.
 *
 * The list that label was hiding — the twenty flats you are still deciding
 * between — now exists separately, in `features/shortlist`, and creates no
 * lead, notifies nobody and is capped by nothing. It is on this device only,
 * which the segment says out loud rather than hiding; see that module.
 */

type Segment = 'shortlist' | 'enquiries' | 'searches' | 'bookings';

export default function ActivityScreen() {
  const router = useRouter();

  /**
   * Which segment to open on.
   *
   * Set by callers that know what they are sending the user to look at — a
   * saved-search notification means the Searches segment, not whichever one
   * happens to be first. Validated against the union rather than cast, so a
   * stale or hand-written link lands on the default instead of rendering
   * nothing.
   */
  const params = useLocalSearchParams<{ segment?: string }>();
  const requested = SEGMENTS.find((option) => option.value === params.segment)?.value;

  const [segment, setSegment] = useState<Segment>(requested ?? 'shortlist');

  return (
    <Screen edges={['top']}>
      {/* A root tab has nowhere to go back TO, so no back affordance. */}
      <ScreenHeader title="Activity" showBack={false} tight />

      <View style={{ paddingHorizontal: screenPadding, paddingVertical: spacing.md }}>
        <Segmented options={SEGMENTS} value={segment} onChange={setSegment} />
      </View>

      {segment === 'shortlist' ? (
        <ShortlistList onOpenSearch={() => router.push('/(tabs)/search')} />
      ) : segment === 'enquiries' ? (
        <InterestedList onOpenSearch={() => router.push('/(tabs)/search')} />
      ) : segment === 'searches' ? (
        <SearchesList />
      ) : (
        <BookingsList />
      )}
    </Screen>
  );
}

/**
 * The shortlist.
 *
 * Needs no account and makes no request: it replays snapshots from disk, the
 * same mechanism `recentlyViewed` uses and for the same reason — refetching to
 * draw a row would inflate the view counter of everything the user is
 * considering. See `features/shortlist/store.ts`.
 *
 * The footnote about the device is not fine print. A user who assumes this
 * syncs will lose work on their next phone and blame the app; saying so is the
 * cost of shipping the honest version of the feature before the server has one.
 */
function ShortlistList({ onOpenSearch }: { onOpenSearch: () => void }) {
  const router = useRouter();
  const theme = useTheme();
  const items = useShortlist();

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  if (items.length === 0) {
    return (
      <NothingSavedYet
        onSelectProperty={openProperty}
        renderPrompt={(compact) => (
          <EmptyState
            compact={compact}
            icon={
              <View
                className="items-center justify-center rounded-full"
                style={{ width: 72, height: 72, backgroundColor: theme.colors.accentMuted }}
              >
                <Ionicons name="bookmark" size={30} color={theme.colors.accent} />
              </View>
            }
            title="Nothing shortlisted yet"
            description="Tap Save on a listing to keep it here while you decide. The owner is not told, and there is no limit."
            actionLabel="Search listings"
            onAction={onOpenSearch}
          />
        )}
      />
    );
  }

  return (
    <FlashList
      data={items}
      keyExtractor={(item) => item.property.id}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
      }}
      ItemSeparatorComponent={RowSeparator}
      ListFooterComponent={
        <Text variant="caption" tone="muted" className="mt-lg text-center">
          Your shortlist is kept on this device. Owners are not notified.
        </Text>
      }
      renderItem={({ item }) => (
        <ShortlistRow entry={item} onPress={openProperty} onRemove={removeFromShortlist} />
      )}
    />
  );
}

/**
 * Bookings and enquiries against builder units.
 *
 * The same rows `/projects/bookings` renders, from the same hook — this
 * segment is where they belong, and that screen stays reachable because it is
 * deep-linked from notifications. `BookingRow` is shared rather than copied so
 * the enquiry-versus-booking distinction has one implementation.
 */
function BookingsList() {
  const router = useRouter();
  const { bookings, isLoading, isRefreshing, error, refresh, signedIn } = useMyBookings();

  // Loading first: during the cold-start session probe nobody is "signed out"
  // yet, they are unknown, and a sign-in prompt shown to a returning user for
  // half a second is a lie the app then retracts.
  if (isLoading) {
    return (
      <View style={{ paddingHorizontal: screenPadding }}>
        {[0, 1].map((i) => (
          <Skeleton key={i} height={88} className="mb-base" radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (!signedIn) {
    return (
      <SignInPrompt
        icon="calendar-outline"
        title="Your bookings"
        description="Units you have booked or enquired about appear here."
      />
    );
  }

  if (error) return <ErrorState title="Could not load your bookings" onRetry={refresh} />;

  if (bookings.length === 0) {
    return (
      <EmptyState
        title="No bookings yet"
        description="Book a unit or send an enquiry from any project to see it here."
        actionLabel="Browse projects"
        onAction={() => router.push('/projects')}
      />
    );
  }

  return (
    <FlashList
      data={bookings}
      keyExtractor={(item) => item._id}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
      }}
      refreshing={isRefreshing}
      onRefresh={refresh}
      renderItem={({ item }) => (
        <BookingRow
          booking={item}
          className=""
          onPress={() => router.push(`/projects/booking/${item._id}`)}
        />
      )}
    />
  );
}

/**
 * Every card on this screen is by definition already saved, so its heart only
 * ever withdraws and the confirmation sheet is never raised from here. It is
 * mounted anyway: the sheet belongs to `useSaveToggle`, and a screen that owns
 * that hook without rendering its sheet is one refactor away from a tap that
 * silently does nothing.
 */
function InterestedSheets({ save }: { save: SaveToggle }) {
  return (
    <EnquirySheet
      visible={save.pending !== null}
      subtitle={save.pending?.locationLabel || save.pending?.title}
      remaining={save.remaining}
      onConfirm={save.confirm}
      onCancel={save.cancel}
    />
  );
}

/** Module-level so the reference is stable; see `PropertyList`'s note on why
 *  these are separators rather than a container `gap`. */
const CardSeparator = () => <View style={{ height: spacing.base }} />;
const RowSeparator = () => <View style={{ height: spacing.md }} />;

const SEGMENTS = [
  // Shortlist first: it is the widest list, the cheapest act, and the one a
  // user opens this tab to look through.
  { label: 'Shortlist', value: 'shortlist' as const },
  // "Enquiries", not "Favourites": adding to this list emails the owner and
  // creates a lead. See `features/properties/interest.ts`.
  { label: 'Enquiries', value: 'enquiries' as const },
  { label: 'Searches', value: 'searches' as const },
  { label: 'Bookings', value: 'bookings' as const },
];

function InterestedList({ onOpenSearch }: { onOpenSearch: () => void }) {
  const router = useRouter();
  const theme = useTheme();
  const { items, isLoading, isRefreshing, error, refresh, used, requiresAuth } =
    useSavedProperties();
  const save = useSaveToggle();

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  if (requiresAuth) {
    return (
      <NothingSavedYet
        onSelectProperty={openProperty}
        renderPrompt={(compact) => (
          <SignInPrompt
            compact={compact}
            icon="heart-outline"
            title="Your interested list"
            description="Listings you tell an owner you are interested in appear here."
          />
        )}
      />
    );
  }

  if (isLoading) return <PropertyListSkeleton />;

  if (error) return <ErrorState title="Could not load your list" onRetry={refresh} />;

  if (items.length === 0) {
    return (
      <NothingSavedYet
        onSelectProperty={openProperty}
        renderPrompt={(compact) => (
          <EmptyState
            compact={compact}
            icon={
              <View
                className="items-center justify-center rounded-full"
                style={{
                  width: 72,
                  height: 72,
                  backgroundColor: theme.colors.brandMuted,
                }}
              >
                <Ionicons name="heart" size={30} color={theme.colors.brand} />
              </View>
            }
            title="Nothing saved yet"
            description="Tap the heart on a listing to enquire about it. Saved listings appear here, up to five at a time."
            actionLabel="Browse properties"
            onAction={onOpenSearch}
          />
        )}
      />
    );
  }

  return (
    <>
    <FlashList
      data={items}
      keyExtractor={(item) => item.id}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
      }}
      /*
        A separator, not `gap`: FlashList positions cells absolutely, so flex
        gap on the content container is inert. See `PropertyList` for the full
        note. 16, matching the browse feed, so the two screens read as one
        product at one density.
      */
      ItemSeparatorComponent={CardSeparator}
      ListHeaderComponentStyle={{ marginBottom: spacing.base }}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={refresh}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      ListHeaderComponent={<EnquiryMeter used={used} />}
      /*
        THE REMOVE ACTION IS ON THE CARD, NOT BETWEEN CARDS.

        This list used to render a card, then a small red "Remove" link in the
        gap beneath it, then the next card — putting the control nearer the
        listing it does NOT act on than the one it does. See
        `SavedPropertyCard` for the full reasoning and for why the
        confirmation dialog went with it.
      */
      renderItem={({ item }) => (
        <SavedPropertyCard
          property={item}
          onPress={openProperty}
          busy={save.isBusy(item.id)}
          onRemove={save.toggle}
        />
      )}
      />

      <InterestedSheets save={save} />
    </>
  );
}

/**
 * The Interested tab with nothing on it — for a guest, and for a signed-in user
 * who has not enquired about anything yet.
 *
 * ---------------------------------------------------------------------------
 * IT USED TO BE A BOX IN THE MIDDLE OF AN EMPTY SCREEN
 *
 * Both states rendered one centred prompt and nothing else, which is the same
 * dead end `SignInPrompt`'s own docstring describes and Profile was fixed for
 * on 2026-08-14. The claim behind it — that a screen about saved things has
 * nothing to show someone with none — was not checked, and it is false.
 *
 * Recently viewed is exactly the list this screen should fall back to. It is
 * device-local history, so it needs no account and it is populated for a guest;
 * it costs no request, because `recentlyViewed.ts` replays a snapshot from disk
 * rather than refetching (which would inflate every listing's view counter —
 * see that module); and it is what someone opening a "Saved" tab with nothing
 * saved is actually looking for. The listing you meant to come back to is far
 * more often one you already opened than one you formally enquired about,
 * especially given enquiring is capped at five and emails the owner.
 *
 * When the history is empty too there is genuinely nothing, and the prompt goes
 * back to filling and centring the screen rather than hanging off the top.
 */
function NothingSavedYet({
  renderPrompt,
  onSelectProperty,
}: {
  /** `compact` is true when something is rendering below the prompt. */
  renderPrompt: (compact: boolean) => React.ReactNode;
  onSelectProperty: (id: string) => void;
}) {
  const viewed = useRecentlyViewed();

  if (viewed.length === 0) return <>{renderPrompt(false)}</>;

  return (
    <ScrollView
      contentContainerStyle={{ paddingBottom: tabBarClearance }}
      showsVerticalScrollIndicator={false}
    >
      {renderPrompt(true)}

      <View style={{ marginTop: spacing.lg }}>
        <View
          className="flex-row items-baseline justify-between"
          style={{ paddingHorizontal: screenPadding, marginBottom: spacing.sm }}
        >
          <SectionLabel>Recently viewed</SectionLabel>
          {/*
            No confirmation, matching Home's copy of this row. Nothing on the
            server changes and the way back is to open a listing; a dialog here
            would be ceremony that teaches users to dismiss the ones that
            matter. See `home/components/RecentlyViewed.tsx`.
          */}
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Clear recently viewed"
            hitSlop={gesture.hitSlop}
            onPress={clearRecentlyViewed}
            className="active:opacity-60"
          >
            <Text variant="footnote" tone="accent">
              Clear
            </Text>
          </Pressable>
        </View>

        <PropertyRail
          items={viewed}
          onSelect={onSelectProperty}
          accessibilityLabel="Recently viewed properties"
        />
      </View>
    </ScrollView>
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

      router.push({ pathname: '/(tabs)/search', params });
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
          // Reports the outcome. The optimistic removal rolls back on failure,
          // so an unconditional toast would confirm a deletion and then let the
          // row reappear underneath it. Same fix as `settings/sessions.tsx`.
          onPress: async () => {
            try {
              await remove(search.id);
              toast.show('Saved search deleted.');
            } catch {
              toast.show('Could not delete that search. Please try again.', 'danger');
            }
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
        onAction={() => router.push('/(tabs)/search')}
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
      }}
      ItemSeparatorComponent={RowSeparator}
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
