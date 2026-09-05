import Ionicons from '@expo/vector-icons/Ionicons';
import { FlashList } from '@shopify/flash-list';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, RefreshControl, ScrollView, View } from 'react-native';

import { SignInPrompt } from '@/auth';
import { DealRow, useMyDeals } from '@/features/deals';
import { matchCity } from '@/features/home';
import { EnquiryMeter, useRemoveInterest, useSavedProperties } from '@/features/saved';
import {
  SavedSearchRow,
  useDeleteSavedSearch,
  useSavedSearches,
  useUpdateSavedSearchAlerts,
  type SavedSearchSummary,
} from '@/features/savedSearches';
import { PropertyRail, clearRecentlyViewed, useRecentlyViewed } from '@/features/properties';
import { BookingRow, useMyBookings } from '@/features/projects';
import {
  MAX_COMPARE,
  CompareBar,
  CompareSheet,
} from '@/features/search';
import {
  ShareShortlistSheet,
  ShortlistNoteSheet,
  ShortlistRow,
  shortlistItemToComparable,
  useShortlistList,
  useShortlistSync,
  useToggleShortlist,
  type ShortlistItem,
} from '@/features/shortlist';
import { gesture, radius, screenPadding, spacing, tabBarClearance, useTheme } from '@/theme';
import type { DealListRow } from '@/types/backend/deal';
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
 *   Deals       in motion         server, both roles, enquiries capped at 5
 *   Searches    watching          server, alerting
 *   Bookings    committed         server, money or a callback
 *
 * ---------------------------------------------------------------------------
 * SHORTLIST AND DEALS ARE TWO LISTS, AND THE SPLIT IS THE WHOLE POINT
 *
 * `GET /properties/saved` reads the same `interestedUsers` array that
 * `POST /properties/interested/:id` writes. There is one server list, and
 * everything on it was an announcement: the owner was emailed and messaged on
 * WhatsApp, a lead exists, and they hold the user's name, email and phone.
 * It is capped at five.
 *
 * Calling that "Favourites" would be the single most misleading label in the
 * app — it implies private, free and unlimited, and it is none of those. It
 * was called Enquiries; since Phase 2 (2026-09-04) the segment renders
 * `GET /deals` instead, which is the same lead seen as a deal: stage, next
 * visit, unread messages, and the owner's side of it too. The segment VALUE is
 * still `enquiries`, because Home and the notification router send it.
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
        <DealsList onOpenSearch={() => router.push('/(tabs)/search')} />
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
  const { items, isLoading, isRefreshing, error, refresh, isOfflineCopy, signedIn } =
    useShortlistList();
  const { toggle } = useToggleShortlist();

  // The handover, if this account has not had one. Cheap when there is nothing
  // to hand over, which is the common case after the first launch.
  useShortlistSync();

  const [sharing, setSharing] = useState(false);
  const [noteFor, setNoteFor] = useState<ShortlistItem | null>(null);
  const [comparing, setComparing] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [showingCompare, setShowingCompare] = useState(false);

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  const remove = useCallback(
    (id: string) => {
      const entry = items.find((item) => item.property.id === id);
      if (entry) toggle(entry.property);
    },
    [items, toggle]
  );

  /**
   * Selection for compare.
   *
   * Capped at `MAX_COMPARE`, the same ceiling the search screen uses, so the
   * table never has to lay out more columns than a phone can read. The
   * category gate `canAddToCompare` applies on the search screen lives there:
   * the shortlist projection carries no `categoryName`, and this list is the
   * user's own selection, so refusing a pairing they deliberately made would
   * be the app second-guessing them with less information than they have.
   */
  const selectedItems = useMemo(
    () =>
      selected
        .map((id) => items.find((item) => item.property.id === id))
        .filter((item): item is ShortlistItem => !!item)
        .map(shortlistItemToComparable),
    [selected, items]
  );

  const toggleSelect = useCallback((id: string) => {
    setSelected((current) => {
      if (current.includes(id)) return current.filter((value) => value !== id);
      if (current.length >= MAX_COMPARE) return current;
      return [...current, id];
    });
  }, []);

  const exitCompare = useCallback(() => {
    setComparing(false);
    setSelected([]);
  }, []);

  if (isLoading) {
    return (
      <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
        {[0, 1, 2].map((index) => (
          <Skeleton key={index} height={94} radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (error) return <ErrorState title="Could not load your shortlist" onRetry={refresh} />;

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
    <>
      <FlashList
        data={items}
        keyExtractor={(item) => item.property.id}
        extraData={selected}
        contentContainerStyle={{
          paddingHorizontal: screenPadding,
          paddingBottom: comparing ? tabBarClearance + 96 : tabBarClearance,
        }}
        ItemSeparatorComponent={RowSeparator}
        refreshControl={
          signedIn ? (
            <RefreshControl
              refreshing={isRefreshing}
              onRefresh={refresh}
              tintColor={theme.colors.textMuted}
              colors={[theme.colors.accent]}
              progressBackgroundColor={theme.colors.surface}
            />
          ) : undefined
        }
        ListHeaderComponentStyle={{ marginBottom: spacing.base }}
        ListHeaderComponent={
          <ShortlistToolbar
            count={items.length}
            signedIn={signedIn}
            comparing={comparing}
            onCompare={() => (comparing ? exitCompare() : setComparing(true))}
            onShare={() => setSharing(true)}
          />
        }
        ListFooterComponent={
          <Text variant="caption" tone="muted" className="mt-lg text-center">
            {signedIn
              ? isOfflineCopy
                ? 'Showing the copy saved on this device. Pull down to refresh.'
                : 'Saved to your account. Owners are not notified, and there is no limit.'
              : 'Kept on this device. Sign in and your shortlist moves to your account.'}
          </Text>
        }
        renderItem={({ item }) => (
          <ShortlistRow
            entry={item}
            onPress={openProperty}
            onRemove={comparing ? undefined : remove}
            onEditNote={comparing || !signedIn ? undefined : setNoteFor}
            selectable={comparing}
            selected={selected.includes(item.property.id)}
            onToggleSelect={toggleSelect}
          />
        )}
      />

      {/*
        The compare bar is the mode indicator, exactly as on the search screen:
        a mode with no on-screen statement of itself is the mode error every
        review of this app is meant to catch. It is `CompareBar` rather than a
        second implementation, so the two screens cannot drift.
      */}
      <CompareBar
        items={selectedItems}
        active={comparing}
        onRemove={toggleSelect}
        onClear={() => setSelected([])}
        onCompare={() => setShowingCompare(true)}
        onExit={exitCompare}
      />

      <CompareSheet
        visible={showingCompare}
        items={selectedItems}
        onClose={() => setShowingCompare(false)}
      />

      <ShareShortlistSheet visible={sharing} onClose={() => setSharing(false)} count={items.length} />

      <ShortlistNoteSheet entry={noteFor} onClose={() => setNoteFor(null)} />
    </>
  );
}

/**
 * The two things you do with a shortlist that are not opening one listing.
 *
 * Compare and Share sit above the list rather than in the screen header,
 * because that header belongs to the whole Activity tab and three of its four
 * segments have nothing to compare or share. Sharing is offered only to a
 * signed-in user: the link is issued by the server against their list, and
 * there is nothing to issue one against for a guest.
 */
function ShortlistToolbar({
  count,
  signedIn,
  comparing,
  onCompare,
  onShare,
}: {
  count: number;
  signedIn: boolean;
  comparing: boolean;
  onCompare: () => void;
  onShare: () => void;
}) {
  const theme = useTheme();

  return (
    <View className="flex-row items-center">
      <Text variant="footnote" tone="secondary" className="flex-1">
        {count} {count === 1 ? 'listing' : 'listings'} saved
      </Text>

      <Pressable
        accessibilityRole="button"
        accessibilityLabel={comparing ? 'Leave compare mode' : 'Compare shortlisted listings'}
        accessibilityState={{ selected: comparing }}
        hitSlop={gesture.hitSlop}
        onPress={onCompare}
        className="flex-row items-center active:opacity-60"
      >
        <Ionicons
          name="git-compare-outline"
          size={17}
          color={comparing ? theme.colors.accent : theme.colors.textMuted}
        />
        <Text variant="footnote" tone={comparing ? 'accent' : 'secondary'} className="ml-xs">
          Compare
        </Text>
      </Pressable>

      {signedIn ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Share your shortlist"
          hitSlop={gesture.hitSlop}
          onPress={onShare}
          className="ml-lg flex-row items-center active:opacity-60"
        >
          <Ionicons name="share-outline" size={17} color={theme.colors.textMuted} />
          <Text variant="footnote" tone="secondary" className="ml-xs">
            Share
          </Text>
        </Pressable>
      ) : null}
    </View>
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

/** Module-level so the reference is stable; see `PropertyList`'s note on why
 *  these are separators rather than a container `gap`. */
const RowSeparator = () => <View style={{ height: spacing.md }} />;

const SEGMENTS = [
  // Shortlist first: it is the widest list, the cheapest act, and the one a
  // user opens this tab to look through.
  { label: 'Shortlist', value: 'shortlist' as const },
  // "Deals" over the value `enquiries`: the value is what Home's tile and the
  // notification deep links send, and the label is what the list now holds.
  // Every deal began as an enquiry, so the older name is not wrong, only
  // narrower than the row. See `features/deals`.
  { label: 'Deals', value: 'enquiries' as const },
  { label: 'Searches', value: 'searches' as const },
  { label: 'Bookings', value: 'bookings' as const },
];

/**
 * The Deals segment.
 *
 * ---------------------------------------------------------------------------
 * ONE LIST FOR BOTH SIDES
 *
 * `GET /deals` answers for the buyer who enquired AND for the owner of the
 * listing, and this list shows both: an owner who is also looking for a flat
 * has one place to see everything in motion. The role is named on the row only
 * when the list actually mixes the two; a pure buyer never reads "Buying" five
 * times.
 *
 * ---------------------------------------------------------------------------
 * THE ENQUIRY CAP DID NOT GO AWAY
 *
 * Every buyer-side deal began as `POST /properties/interested/:id`, which is
 * capped at five, and this is still where a user comes to make room. So the
 * meter stays at the top, read from the same `GET /properties/saved` the old
 * list rendered, and a buyer-side row whose listing is still on that list
 * gets an overflow that withdraws the enquiry. Withdrawing frees the slot and
 * leaves the deal where it is: the lead the owner already holds does not
 * un-exist, so the row does not vanish and the copy does not claim it will.
 */
function DealsList({ onOpenSearch }: { onOpenSearch: () => void }) {
  const router = useRouter();
  const theme = useTheme();
  const {
    deals,
    isLoading,
    isRefreshing,
    isFetchingMore,
    hasMore,
    error,
    refresh,
    loadMore,
    requiresAuth,
  } = useMyDeals();
  // The cap, and which listings still hold a slot. Enabled by the same
  // session the deals query is, so a guest sends neither request.
  const saved = useSavedProperties();
  const { remove } = useRemoveInterest();

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);
  const openDeal = useCallback((leadId: string) => router.push(`/deal/${leadId}`), [router]);

  const showRole = useMemo(() => {
    const roles = new Set(deals.map((deal) => deal.role));
    return roles.size > 1;
  }, [deals]);

  const savedIds = useMemo(() => new Set(saved.items.map((item) => item.id)), [saved.items]);

  const withdraw = useCallback(
    (deal: DealListRow) => {
      const propertyId = deal.property?.id;
      if (!propertyId) return;
      Alert.alert(
        'Withdraw this enquiry?',
        'This frees one of your five enquiry slots. The owner already has your details and the deal stays in this list.',
        [
          { text: 'Cancel', style: 'cancel' },
          // No toast: the removal is optimistic and rolls back on failure, so
          // a confirmation here could outlive the thing it confirmed. The
          // meter dropping and the overflow leaving the row are the feedback.
          { text: 'Withdraw', style: 'destructive', onPress: () => remove(propertyId) },
        ]
      );
    },
    [remove]
  );

  if (requiresAuth) {
    return (
      <NothingSavedYet
        onSelectProperty={openProperty}
        renderPrompt={(compact) => (
          <SignInPrompt
            compact={compact}
            icon="chatbubbles-outline"
            title="Your deals"
            description="Every enquiry you send, and every one you receive on your listing, becomes a deal you can follow here."
          />
        )}
      />
    );
  }

  if (isLoading) return <DealListSkeleton />;

  if (error) return <ErrorState title="Could not load your deals" onRetry={refresh} />;

  if (deals.length === 0) {
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
                <Ionicons name="chatbubbles" size={30} color={theme.colors.brand} />
              </View>
            }
            title="No deals yet"
            description="A deal starts when you tell an owner you are interested. It keeps the visit, the messages and the close in one place, up to five enquiries at a time."
            actionLabel="Browse properties"
            onAction={onOpenSearch}
          />
        )}
      />
    );
  }

  return (
    <FlashList
      data={deals}
      keyExtractor={(item) => item.id}
      extraData={savedIds}
      contentContainerStyle={{
        paddingHorizontal: screenPadding,
        paddingBottom: tabBarClearance,
      }}
      ItemSeparatorComponent={RowSeparator}
      ListHeaderComponentStyle={{ marginBottom: spacing.base }}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={() => {
            refresh();
            saved.refresh();
          }}
          tintColor={theme.colors.textMuted}
          colors={[theme.colors.accent]}
          progressBackgroundColor={theme.colors.surface}
        />
      }
      // The meter reads the saved list, which can fail on its own; a failed
      // count is omitted rather than shown as "0 of 5", which would be a lie
      // about the cap on exactly the screen that exists to manage it.
      ListHeaderComponent={
        !saved.isLoading && !saved.error ? <EnquiryMeter used={saved.used} /> : null
      }
      onEndReached={loadMore}
      onEndReachedThreshold={0.4}
      ListFooterComponent={
        isFetchingMore ? (
          <ActivityIndicator color={theme.colors.textMuted} style={{ marginTop: spacing.lg }} />
        ) : hasMore ? null : (
          <Text variant="caption" tone="muted" className="mt-lg text-center">
            Tap a deal to see its visits, messages and close.
          </Text>
        )
      }
      renderItem={({ item }) => (
        <DealRow
          deal={item}
          showRole={showRole}
          onPress={openDeal}
          onOverflow={
            item.role === 'buyer' && item.property && savedIds.has(item.property.id)
              ? withdraw
              : undefined
          }
        />
      )}
    />
  );
}

/** Mirrors `DealRow`'s geometry: a thumbnail beside two lines and a badge. */
function DealListSkeleton() {
  return (
    <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
      <Skeleton height={64} radius={radius.lg} />
      {[0, 1, 2].map((index) => (
        <View
          key={index}
          className="flex-row rounded-lg bg-surface p-md"
          style={{ borderRadius: radius.lg }}
        >
          <Skeleton width={64} height={64} radius={radius.md} />
          <View className="ml-md flex-1">
            <Skeleton width="70%" height={16} />
            <Skeleton width="45%" height={14} className="mt-sm" />
            <Skeleton width="55%" height={12} className="mt-sm" />
          </View>
        </View>
      ))}
    </View>
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
          onToggleAlerts={setAlerts}
          onDelete={confirmDelete}
        />
      )}
    />
  );
}
