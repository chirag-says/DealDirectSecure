import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';
import { RefreshControl, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { qk } from '@/api';
import { useAuth } from '@/auth';
import {
  ActivitySnapshot,
  CityGrid,
  CityPickerSheet,
  CollectionRail,
  HOME_COLLECTION_IDS,
  HomeHeader,
  HomeHero,
  ListingCard,
  RecentlyViewed,
  Section,
  UpdatesPreview,
  findCollection,
  setSelectedCity,
  usePopularListings,
  useSelectedCity,
  type ListingCardState,
  type SnapshotTile,
} from '@/features/home';
import { useLeads } from '@/features/leads';
import { useMyProperties } from '@/features/listings';
import { hrefForTarget, resolveNotificationTarget, useNotifications } from '@/features/notifications';
import { PropertyRail, type ListingIntent } from '@/features/properties';
import { ProjectRail, useRecentProjects } from '@/features/projects';
import { useSavedProperties } from '@/features/saved';
import { useSavedSearches } from '@/features/savedSearches';
import { ResumeSearchCard, clearResumableSearch, useResumableSearch } from '@/features/search';
import { useShortlist } from '@/features/shortlist';
import { ToolsRow } from '@/features/tools';
import { Reveal, ScrollRevealProvider, useScrollRevealHost } from '@/lib';
import { screenPadding, spacing, tabBarClearance, useTheme } from '@/theme';
import type { AppNotification } from '@/types/backend/notification';
import type { PropertySearchParams } from '@/types/backend/property';
import { PressableScale, Screen, Text } from '@/ui';

/**
 * Home — where a session starts.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE, AND THE TWO MISTAKES IT SITS BETWEEN
 *
 * This screen has been wrong in both directions. It began as the website's
 * landing page: a pitch headline, a benefits strip, a "why choose us" block and
 * a closing "Ready to find your home?" slab, none of which a person who has
 * already installed the app needs. Then it was deleted outright and folded into
 * Search, which fixed the marketing and lost the thing a returning user
 * actually opens with — no surface answered "what is happening with mine".
 *
 * What it is now is the shape the large Indian portals converged on:
 *
 *   Hero            who, where, what, and a field to say it in
 *   Recent activity what you already have in flight
 *   Inventory       popular listings, new projects, curated rails, cities
 *   Tools           the calculators, next to the priciest inventory
 *
 * The hero carries ONE claim, above the search field rather than in front of
 * it. Everything below the hero is either the user's own activity or live
 * inventory. Nothing on this screen explains the company.
 *
 * ---------------------------------------------------------------------------
 * REQUEST BUDGET, AND WHY `Reveal` IS NOT OPTIONAL
 *
 * `/properties/search` allows 20 requests per minute per IP, shared by everyone
 * behind a carrier NAT, and every inventory rail below is one of them. Sections
 * under the fold are wrapped in `Reveal`, which withholds the MOUNT — and so
 * the query — until the section is about a screen away. The hero is static and
 * paints before anything resolves, so the screen is never blank.
 *
 * The activity blocks cost nothing extra: shortlist, resume and recently-viewed
 * are MMKV snapshots, and saved / saved-searches / notifications are the same
 * queries Activity and Updates run, shared by key. A guest fires no personal
 * requests at all.
 */
export default function HomeScreen() {
  const router = useRouter();
  const theme = useTheme();
  const queryClient = useQueryClient();
  const { status, user } = useAuth();

  const signedIn = status === 'authenticated';
  const isOwner = user?.role === 'owner';

  const [refreshing, setRefreshing] = useState(false);
  const [cityPickerOpen, setCityPickerOpen] = useState(false);

  /**
   * The scroll host.
   *
   * Home needs the offset for two things — the reveal system below the fold,
   * and the sticky header above it — and the header renders OUTSIDE the scroll
   * view, so it cannot read the context from within. Owning the host means
   * both are driven by the SAME shared value and there is still exactly one
   * scroll listener on the UI thread.
   */
  const { context: scrollHost, onScroll, onLayout } = useScrollRevealHost();

  /**
   * The scroll offset at which the hero's search field reaches the header, so
   * the header's copy can take over at exactly that pixel. Reported by the
   * hero, which measures its own field — see the handover note in
   * `HomeHeader`.
   */
  const [pinOffset, setPinOffset] = useState(0);

  /**
   * The search text, owned here because the field is rendered TWICE — in the
   * hero and in the pinned header — and the two are one field to the user.
   * Whichever is on screen shows what was typed into the other.
   */
  const [searchText, setSearchText] = useState('');

  const city = useSelectedCity();

  /* Local, free, and correct while signed out. */
  const shortlist = useShortlist();
  const resumable = useResumableSearch();

  /* Shared with Activity and Updates; all no-op when signed out. */
  const saved = useSavedProperties();
  const searches = useSavedSearches();
  const notifications = useNotifications();

  /* Owner only, gated at the query because hooks cannot be called
     conditionally. Neither of these is auth-gated internally. */
  const ownerProperties = useMyProperties({ enabled: signedIn && isOwner });
  const ownerLeads = useLeads('new', { enabled: signedIn && isOwner });

  /**
   * Every affordance lands on Search, which owns results, pagination, filters
   * and compare. Home never renders a feed of its own.
   *
   * The selected city rides along on all of them, which is what makes the
   * hero's city chip mean something rather than decorate the top of the screen.
   */
  const openSearch = useCallback(
    (
      params?: PropertySearchParams & {
        search?: string;
        listingType?: ListingIntent;
        browse?: string;
      }
    ) => {
      const merged = { ...(params ?? {}) } as Record<string, string>;
      if (city && !merged.city) merged.city = city.id;
      if (Object.keys(merged).length === 0) merged.browse = '1';
      router.push({ pathname: '/(tabs)/search', params: merged });
    },
    [router, city]
  );

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  const openActivity = useCallback(
    (segment: string) => router.push({ pathname: '/(tabs)/activity', params: { segment } }),
    [router]
  );

  /**
   * Notification taps go through the same validated resolver the Updates tab
   * uses. Home must not be a second, laxer way into the same navigation.
   */
  const openNotification = useCallback(
    (notification: AppNotification) => {
      const target = resolveNotificationTarget(notification);
      router.push(target ? hrefForTarget(target) : '/(tabs)/updates');
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
  }, [
    signedIn,
    shortlist.length,
    saved.isLoading,
    saved.used,
    searches.isLoading,
    searches.items.length,
    openActivity,
  ]);

  const listingState = useMemo<ListingCardState>(() => {
    if (!signedIn) return { kind: 'guest' };
    if (!isOwner) return { kind: 'buyer' };
    if (ownerProperties.isLoading) return { kind: 'ownerListed', newLeads: null };
    if ((ownerProperties.properties?.length ?? 0) === 0) return { kind: 'ownerEmpty' };
    return { kind: 'ownerListed', newLeads: ownerLeads.total };
  }, [signedIn, isOwner, ownerProperties.isLoading, ownerProperties.properties, ownerLeads.total]);

  const openListing = useCallback(() => {
    if (!signedIn) return router.push('/(auth)/login');
    if (!isOwner) return router.push('/(tabs)/profile');
    if ((ownerProperties.properties?.length ?? 0) === 0) return router.push('/owner/property/new');
    return router.push('/owner/properties');
  }, [signedIn, isOwner, ownerProperties.properties, router]);

  /**
   * Prefix invalidation over the keys this screen reads, so a query added later
   * is covered without anyone remembering to come back here. Unrevealed
   * sections have no cache entry, so this costs only what is on screen.
   */
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.properties }),
        queryClient.invalidateQueries({ queryKey: qk.projects }),
        queryClient.invalidateQueries({ queryKey: qk.savedProperties() }),
        queryClient.invalidateQueries({ queryKey: qk.notifications }),
        queryClient.invalidateQueries({ queryKey: qk.savedSearches }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [queryClient]);

  const hasUnread = notifications.items.some((item) => !item.isRead);

  return (
    // The screen's own background is the brand colour so the safe area above
    // the hero is filled by the hero rather than by a white strip; the scroll
    // content paints the page colour back over everything below it.
    // `edges` is empty and the hero paints its own safe area, because the
    // sticky header has to be able to sit UNDER the status bar. A `Screen` that
    // insets the top would leave a strip of page colour above a bar whose whole
    // purpose is to be the top of the screen.
    <Screen edges={[]} style={{ backgroundColor: theme.colors.brand }}>
      <ScrollRevealProvider value={scrollHost}>
        <Animated.ScrollView
          onScroll={onScroll}
          onLayout={onLayout}
          scrollEventThrottle={16}
          showsVerticalScrollIndicator={false}
          // The hero's autocomplete rows live inside this scroll view; without
          // this, the first tap on a suggestion only dismisses the keyboard and
          // the selection is lost. "handled" lets the row's own press through.
          keyboardShouldPersistTaps="handled"
          contentContainerStyle={{
            paddingBottom: tabBarClearance,
            backgroundColor: theme.colors.background,
          }}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={theme.colors.brand}
              colors={[theme.colors.brand]}
              // Clear of the sticky header, or the spinner appears behind it.
              progressViewOffset={56}
            />
          }
        >
          <View>
            <HomeHero
              city={city}
              scrollY={scrollHost.offset}
              searchValue={searchText}
              onSearchValueChange={setSearchText}
              onPinOffsetChange={setPinOffset}
              // The hero field runs the search itself now; an empty term means
              // "browse everything", which `openSearch` already encodes.
              onSubmitSearch={(term) => openSearch(term ? { search: term } : undefined)}
              onOpenProperty={openProperty}
              onIntent={(intent) =>
                intent === 'projects'
                  ? router.push('/projects')
                  : openSearch({ listingType: intent })
              }
            />
          </View>

        {/* The user's own things, directly under the hero and above any
            inventory: a returning user's answer is far more often something
            they already touched than something a rail picked. Every block here
            renders null when it has nothing, so a first session drops straight
            through to the listings. */}
        <View style={{ paddingHorizontal: screenPadding, gap: spacing.lg, paddingTop: spacing.lg }}>
          {tiles.length > 0 ? <ActivitySnapshot tiles={tiles} /> : null}

          {resumable ? (
            <ResumeSearchCard
              search={resumable}
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
        </View>

        {/* Replays a disk snapshot, so it is the one row that costs nothing and
            the only one not deferred — it should be on screen the instant a
            returning user opens the app. */}
        <RecentlyViewed onSelectProperty={openProperty} />

        <Reveal placeholder={<SectionPlaceholder />}>
          <PopularListings onViewAll={openSearch} onSelectProperty={openProperty} />
        </Reveal>

        <Reveal placeholder={<SectionPlaceholder />}>
          <BuilderProjects
            onSelectProject={(id) => router.push(`/projects/${id}`)}
            onViewAll={() => router.push('/projects')}
          />
        </Reveal>

        <View style={{ paddingHorizontal: screenPadding, paddingTop: spacing.lg }}>
          <ListingCard state={listingState} onPress={openListing} />
        </View>

        {/*
          The research tools, directly under the builder projects.

          Builder inventory is the most expensive thing on this screen and the
          most likely to be out of a given buyer's reach, so the question it
          raises is "what can I actually afford?". Answering that in the next
          section rather than four rails later is the whole point of the
          placement.
        */}
        <Reveal placeholder={<SectionPlaceholder height={220} />}>
          <Section
            title="Work out your budget"
            subtitle="Before you fall for something you cannot buy"
          >
            <ToolsRow onOpen={(route) => router.push(route)} />
          </Section>
        </Reveal>

        {/*
          The editorial rails. Each is revealed separately, so its query fires
          only as it approaches the viewport — and each unmounts itself if it
          cannot meet its own `minResults`. See `HOME_COLLECTION_IDS` for why
          this is three rows and not the full registry of fifteen.
        */}
        {HOME_COLLECTION_IDS.map((id) => {
          const collection = findCollection(id);
          if (!collection) return null;
          return (
            <Reveal key={id} placeholder={<SectionPlaceholder />}>
              <CollectionRail
                collection={collection}
                onViewAll={openSearch}
                onSelectProperty={openProperty}
              />
            </Reveal>
          );
        })}

        <Reveal placeholder={<SectionPlaceholder height={300} />}>
          <Section title="Explore by city" subtitle="Every count below is live inventory">
            <CityGrid onSelect={(search) => openSearch({ search })} />
          </Section>
          </Reveal>
        </Animated.ScrollView>
      </ScrollRevealProvider>

      {/* Rendered AFTER the scroll view so it paints above it, and outside the
          provider because it is chrome rather than revealable content. It is
          visible at every scroll position; only its search row reacts. */}
      <HomeHeader
        scrollY={scrollHost.offset}
        pinOffset={pinOffset}
        name={user?.name}
        avatarUri={user?.profileImage}
        hasUnread={hasUnread}
        city={city}
        searchValue={searchText}
        onSearchValueChange={setSearchText}
        onSubmitSearch={(term) => openSearch(term ? { search: term } : undefined)}
        onOpenProperty={openProperty}
        onOpenProfile={() => router.push('/(tabs)/profile')}
        onOpenUpdates={() => router.push('/(tabs)/updates')}
        onOpenCityPicker={() => setCityPickerOpen(true)}
        canList={listingState.kind === 'ownerEmpty'}
        onAddListing={openListing}
      />

      <CityPickerSheet
        visible={cityPickerOpen}
        selected={city}
        onSelect={setSelectedCity}
        onClose={() => setCityPickerOpen(false)}
      />
    </Screen>
  );
}

/**
 * Most viewed.
 *
 * The subtitle changes with `isComplete`, and that is not decoration. While the
 * whole corpus fits in one page the ranking is genuinely the most-viewed
 * listings on DealDirect. Once it does not, the row is showing the most viewed
 * among the newest hundred, which is a weaker claim, and the copy stops making
 * the stronger one.
 */
function PopularListings({
  onViewAll,
  onSelectProperty,
}: {
  onViewAll: (params: PropertySearchParams & { browse?: string }) => void;
  onSelectProperty: (id: string) => void;
}) {
  const { items, isLoading, isComplete, error, retry } = usePopularListings();

  /*
    A failed fetch used to be indistinguishable from an empty corpus, because
    both arrive here as `items.length === 0` and the rail returned null. With
    every rail on the screen doing that, a total outage rendered Home as the
    hero above a blank page: no message, nothing to retry, nothing to suggest
    the app was not simply empty.

    Silence is still right when there is genuinely nothing to show. It is not
    right when we failed to ask.
  */
  if (error && !isLoading) {
    return (
      <Section title="Popular right now">
        <RailError onRetry={retry} />
      </Section>
    );
  }

  if (!isLoading && items.length === 0) return null;

  return (
    <Section
      title="Popular right now"
      subtitle={isComplete ? 'Most viewed homes right now' : 'Most viewed among our newest listings'}
      actionLabel="View all"
      onAction={() => onViewAll({ sort: 'newest', browse: '1' })}
    >
      <PropertyRail
        items={items}
        loading={isLoading}
        onSelect={onSelectProperty}
        accessibilityLabel="Popular listings"
        showIndicator
      />
    </Section>
  );
}

/**
 * Builder developments, newest first.
 *
 * Sorted server-side by `createdAt`, which is the only ordering `listProjects`
 * offers, so "recent" is what the endpoint natively returns rather than a
 * ranking invented here. This is also the only surface in the app where builder
 * inventory appears at all: `/properties/search` excludes builder-posted
 * listings by design.
 */
function BuilderProjects({
  onSelectProject,
  onViewAll,
}: {
  onSelectProject: (id: string) => void;
  onViewAll: () => void;
}) {
  const { items, isLoading, total, error, retry } = useRecentProjects();

  // Same rule as the popular rail above: absent is silent, failed is not.
  if (error && !isLoading) {
    return (
      <Section title="New projects">
        <RailError onRetry={retry} />
      </Section>
    );
  }

  if (!isLoading && items.length === 0) return null;

  return (
    <Section
      title="New projects"
      subtitle="Direct from the builder"
      // Only offer "View all" when there is more than the rail already shows. A
      // link to a screen holding the same five cards is a dead end wearing a
      // chevron.
      actionLabel={total > items.length ? 'View all' : undefined}
      onAction={total > items.length ? onViewAll : undefined}
    >
      <ProjectRail
        items={items}
        loading={isLoading}
        onSelect={onSelectProject}
        accessibilityLabel="Builder projects"
      />
    </Section>
  );
}

/**
 * A rail that could not load, stated in the rail's own space.
 *
 * Deliberately small. This is one row of a scrolling page, not the screen's
 * subject, and a full `ErrorState` in a rail slot would make a failed
 * inventory strip look like the app had broken. It says what happened and
 * offers the one useful action.
 */
function RailError({ onRetry }: { onRetry: () => void }) {
  return (
    <View style={{ paddingHorizontal: screenPadding, gap: spacing.xs }}>
      <Text variant="callout" tone="secondary">
        We could not load these right now.
      </Text>
      <PressableScale
        accessibilityRole="button"
        accessibilityLabel="Try loading again"
        onPress={onRetry}
        style={{ alignSelf: 'flex-start' }}
      >
        <Text variant="footnote" tone="accent">
          Try again
        </Text>
      </PressableScale>
    </View>
  );
}

/**
 * Occupies roughly the height of a real section while unrevealed, so sections
 * below do not slide upward as each one loads and drag the content the user is
 * reading out from under them.
 */
function SectionPlaceholder({ height = 320 }: { height?: number }) {
  return <View style={{ height }} />;
}
