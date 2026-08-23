import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';

import { qk } from '@/api';
import { useAuth } from '@/auth';
import {
  ActivitySnapshot,
  BrowseRow,
  HomeGreeting,
  ListingCard,
  RecentlyViewed,
  Section,
  UpdatesPreview,
  type ListingCardState,
  type SnapshotTile,
} from '@/features/home';
import { useMyProperties } from '@/features/listings';
import { useLeads } from '@/features/leads';
import { resolveNotificationTarget, useNotifications } from '@/features/notifications';
import { useSavedProperties } from '@/features/saved';
import { useSavedSearches } from '@/features/savedSearches';
import {
  ResumeSearchCard,
  SearchTrigger,
  clearResumableSearch,
  useResumableSearch,
} from '@/features/search';
import { useShortlist } from '@/features/shortlist';
import { screenPadding, spacing, tabBarClearance } from '@/theme';
import type { AppNotification } from '@/types/backend/notification';
import { Refreshable, Screen } from '@/ui';

/**
 * Home — "what should I do next?".
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS, AND WHAT IT IS NOT
 *
 * Home was a marketing landing page, then for one iteration it did not exist
 * at all — folded into Search on the argument that a search tool is what an app
 * opens with. That was half right. Search IS the tool, but nothing in the app
 * then answered the question a returning user actually arrives with, which is
 * not "what exists" but "what is happening with mine".
 *
 * So this screen is a command centre, and the test for every block on it is
 * whether it is ABOUT THIS USER. A greeting, a way into search, what they have
 * in flight, what changed, what they were looking at, and the one card that
 * covers listing a property. Nothing here explains DealDirect, and nothing
 * here browses inventory — inventory is Search, one tap away, and duplicating
 * it would recreate the two-tabs-one-job problem this app already had.
 *
 * It is deliberately SHORT. Every section can be absent, and most are for a
 * new user: a guest with no history sees a greeting, a search field, a browse
 * row and the listing card, and that is the whole screen. It fills in as the
 * user does things, which is what makes it feel like theirs.
 *
 * ---------------------------------------------------------------------------
 * REQUEST BUDGET
 *
 * A guest fires ZERO requests here. The shortlist, the resumable search and
 * recently-viewed are all MMKV snapshots, and the browse tiles are a static
 * table.
 *
 * A signed-in buyer fires three, and not one of them is new: `saved`,
 * `saved-searches/mine` and `notifications` are the same queries Activity and
 * Updates run, sharing TanStack's cache by key. Opening Home first makes
 * Activity instant rather than costing anything extra.
 *
 * An owner fires two more, `my-properties` and `leads`, both shared with the
 * owner hub. `/properties/search` — the endpoint limited to 20 requests a
 * minute across everyone behind a carrier NAT — is not called here at all. The
 * old Home called it five times.
 */
export default function HomeScreen() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { status, user } = useAuth();

  const signedIn = status === 'authenticated';
  const isOwner = user?.role === 'owner';

  const [refreshing, setRefreshing] = useState(false);

  /* Local, free, and correct while signed out. */
  const shortlist = useShortlist();
  const resumable = useResumableSearch();

  /* Shared with Activity. Both hooks no-op when signed out. */
  const saved = useSavedProperties();
  const searches = useSavedSearches();

  /* Shared with Updates. */
  const notifications = useNotifications();

  /* Owner only, and gated at the QUERY rather than by not calling the hook —
     hooks cannot be called conditionally. Neither of these is auth-gated
     internally (the owner screens they were written for sit behind
     `OwnerOnly`), so without this a guest's Home would fire two requests it
     has no business making and take two 401s for them. */
  const ownerProperties = useMyProperties({ enabled: signedIn && isOwner });
  const ownerLeads = useLeads('new', { enabled: signedIn && isOwner });

  const openSearch = useCallback(() => router.push('/(tabs)/search'), [router]);

  const openActivity = useCallback(
    (segment: string) => router.push({ pathname: '/(tabs)/activity', params: { segment } }),
    [router]
  );

  /**
   * Notification taps go through the same resolver the Updates tab uses, which
   * validates the target rather than following a server-supplied `actionUrl`.
   * Home must not be a second, laxer way into the same navigation.
   */
  const openNotification = useCallback(
    (notification: AppNotification) => {
      const target = resolveNotificationTarget(notification);
      if (!target) {
        router.push('/(tabs)/updates');
        return;
      }
      if (target.kind === 'property') router.push(`/property/${target.id}`);
      else if (target.kind === 'leads') router.push('/owner/leads');
      else if (target.kind === 'dealReward') router.push(`/claim-reward/${target.verificationId}`);
      else router.push({ pathname: '/(tabs)/activity', params: { segment: 'searches' } });
    },
    [router]
  );

  const tiles = useMemo<SnapshotTile[]>(() => {
    if (!signedIn) return [];
    return [
      {
        id: 'shortlist',
        label: 'Shortlisted',
        value: shortlist.length,
        icon: 'bookmark-outline',
        onPress: () => openActivity('shortlist'),
      },
      {
        id: 'enquiries',
        label: 'Enquiries',
        value: saved.isLoading ? null : saved.used,
        icon: 'chatbubble-ellipses-outline',
        onPress: () => openActivity('enquiries'),
      },
      {
        id: 'searches',
        label: 'Saved searches',
        value: searches.isLoading ? null : searches.items.length,
        icon: 'notifications-outline',
        onPress: () => openActivity('searches'),
      },
    ];
  }, [signedIn, shortlist.length, saved.isLoading, saved.used, searches.isLoading, searches.items.length, openActivity]);

  /**
   * Which listing card to draw, and where it goes.
   *
   * The routing mirrors what the dock's Post action used to do — guests to
   * login, everyone else to the owner surface — with the buyer case now
   * landing on Profile, where the phone-verification upgrade actually lives,
   * rather than on a form that would refuse them.
   */
  const listingState = useMemo<ListingCardState>(() => {
    if (!signedIn) return { kind: 'guest' };
    if (!isOwner) return { kind: 'buyer' };
    if (ownerProperties.isLoading) return { kind: 'ownerListed', newLeads: null };
    if ((ownerProperties.properties?.length ?? 0) === 0) return { kind: 'ownerEmpty' };
    return { kind: 'ownerListed', newLeads: ownerLeads.total };
  }, [signedIn, isOwner, ownerProperties.isLoading, ownerProperties.properties, ownerLeads.total]);

  const openListingCard = useCallback(() => {
    if (!signedIn) {
      router.push('/(auth)/login');
      return;
    }
    if (!isOwner) {
      router.push('/(tabs)/profile');
      return;
    }
    if ((ownerProperties.properties?.length ?? 0) === 0) {
      router.push('/owner/property/new');
      return;
    }
    router.push('/owner/properties');
  }, [signedIn, isOwner, ownerProperties.properties, router]);

  /**
   * Prefix invalidation over the keys this screen reads, so a query added here
   * later is covered without anyone remembering to come back. Nothing invalid-
   * ates `qk.properties`: Home makes no search request, and invalidating it
   * would spend the search limiter on a pull the user made to refresh their own
   * activity.
   */
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.savedProperties() }),
        queryClient.invalidateQueries({ queryKey: qk.notifications }),
        queryClient.invalidateQueries({ queryKey: qk.savedSearches }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [queryClient]);

  return (
    <Screen edges={['top']}>
      <Refreshable
        contentContainerStyle={{
          paddingHorizontal: screenPadding,
          paddingBottom: tabBarClearance,
          gap: spacing.lg,
        }}
        refreshing={refreshing}
        onRefresh={signedIn ? onRefresh : undefined}
      >
        <HomeGreeting
          name={user?.name}
          avatarUri={user?.profileImage}
          onOpenProfile={() => router.push('/(tabs)/profile')}
        />

        {/* The one control every visit starts from. A trigger rather than a
            live field: typing belongs on Search, which owns the suggestion
            panel, the recent-search history and the results underneath. Two
            editable search fields in one app is two places for the query to
            live. */}
        <SearchTrigger onPress={openSearch} />

        {tiles.length > 0 ? <ActivitySnapshot tiles={tiles} /> : null}

        {resumable ? (
          <ResumeSearchCard
            search={resumable}
            /* Search reads the stored record itself; passing filters through
               the query string would drop the four client-only facets. */
            onResume={() => router.push({ pathname: '/(tabs)/search', params: { resume: '1' } })}
            onDismiss={clearResumableSearch}
          />
        ) : null}

        {signedIn ? (
          <UpdatesPreview
            items={notifications.items}
            onOpen={openNotification}
            onSeeAll={() => router.push('/(tabs)/updates')}
          />
        ) : null}

        <ListingCard state={listingState} onPress={openListingCard} />

        {/* Replays a disk snapshot, so it costs nothing and works signed out.
            Renders null with no history. */}
        <RecentlyViewed onSelectProperty={(id) => router.push(`/property/${id}`)} />

        {/* The one browse affordance on Home, and it is here because a first
            session has nothing else: no history, no searches, nothing in
            flight. Static table, no request. Everything deeper — collections,
            cities, projects — is Search's job. */}
        <Section title="Browse by type">
          <BrowseRow
            onSelect={(term) =>
              router.push({ pathname: '/(tabs)/search', params: { search: term } })
            }
          />
        </Section>
      </Refreshable>
    </Screen>
  );
}
