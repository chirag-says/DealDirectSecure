import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { RefreshControl, View } from 'react-native';

import { qk } from '@/api';
import {
  AboutDealDirect,
  CityGrid,
  CollectionRail,
  CtaBanner,
  HOME_COLLECTION_IDS,
  Hero,
  RecentlyViewed,
  Section,
  TrustStrip,
  findCollection,
  usePopularListings,
} from '@/features/home';
import { useNotifications } from '@/features/notifications';
import { PropertyRail, type ListingIntent } from '@/features/properties';
import { ProjectRail, useRecentProjects } from '@/features/projects';
import { ToolsRow } from '@/features/tools';
import { Reveal, RevealScrollView } from '@/lib';
import { spacing, useTheme } from '@/theme';
import type { PropertySearchParams } from '@/types/backend/property';

/**
 * Home: discovery, not browsing.
 *
 *   Hero              white header, search, "Find Your Dream Home", Buy/Rent/Post
 *   Recently viewed   replayed from disk, no request, absent on a first session
 *   Popular Listings  ranked by view count
 *   Trust strip       three claims about how the product works
 *   Builder Projects  newest builder developments
 *   Collection rails  three of fifteen, each gated on live counts
 *   Budget tools      affordability and EMI
 *   Why DealDirect    the pitch, once, as three numbered lines
 *   Explore by City   live counts
 *   CTA
 *
 * Nothing here paginates and nothing here filters. Every affordance routes to
 * the one canonical results screen with a filter prefilled, so the app has a
 * single infinite scroll, a single filter sheet and a single sort.
 *
 * Home used to mount `FontOverrideProvider` itself, which is what made it the
 * only screen in DM Sans. That provider now lives at the root layout and
 * covers the whole app, so this screen no longer does anything special with
 * type — see `theme/fonts.ts`.
 *
 * ---------------------------------------------------------------------------
 * DEFERRED MOUNTING
 *
 * `/properties/search` allows 20 requests per minute per IP, shared across
 * everyone behind a carrier NAT. Sections below the fold are wrapped in
 * `Reveal`, which withholds the MOUNT — and therefore the query — until the
 * section is within about a screen of the viewport. The hero is static and
 * paints before any request resolves, so the screen is never blank.
 *
 * ---------------------------------------------------------------------------
 * THE COLLECTIONS RAILS
 *
 * Mounted 2026-08-13, having sat built-but-unrendered since M3.
 * `features/home/collections.ts` holds fifteen curated rails (Luxury, Starter
 * Homes, Sea View and so on), each gated on live result counts — but only the
 * three in `HOME_COLLECTION_IDS` are rendered, because fifteen more queries
 * would put one scroll of this screen over the search limiter. That constant's
 * doc comment is where to change the selection.
 */

export default function HomeScreen() {
  const router = useRouter();
  const theme = useTheme();
  const queryClient = useQueryClient();

  const [refreshing, setRefreshing] = useState(false);

  /**
   * The unread badge on the hero's bell.
   *
   * Read here rather than inside `Hero` so the hero stays a presentational
   * component with no data dependency of its own, and so the one notifications
   * query is owned by the screen that also refreshes it. The hook is a no-op
   * when signed out.
   */
  const { badgeLabel: notificationBadge } = useNotifications();

  /**
   * Every Home affordance lands on the Search tab, which owns results,
   * pagination, filters and compare. Home never fetches a feed of its own.
   *
   * `browse: '1'` is how an affordance says "show everything" — the Search tab
   * treats an absence of criteria as a real results state only when told to,
   * otherwise tapping the tab directly would wipe whatever the user had.
   */
  const openSearch = useCallback(
    (
      params?: PropertySearchParams & {
        search?: string;
        listingType?: ListingIntent;
        browse?: string;
        openFilters?: string;
      }
    ) => {
      router.push({ pathname: '/properties', params: (params ?? {}) as Record<string, string> });
    },
    [router]
  );

  /** A committed term from the hero field. Empty means browse everything. */
  const submitSearch = useCallback(
    (term: string) => openSearch(term ? { search: term } : { browse: '1' }),
    [openSearch]
  );

  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);
  const openProject = useCallback((id: string) => router.push(`/projects/${id}`), [router]);

  /**
   * Prefix invalidation over a list of keys, so a query added later is covered
   * by refresh without anyone remembering to come back here. Unrevealed
   * sections have no cache entry, so this costs only what is on screen.
   */
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.properties }),
        queryClient.invalidateQueries({ queryKey: qk.projects }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [queryClient]);

  return (
    <View className="flex-1 bg-background">
        <RevealScrollView
          contentContainerStyle={{ paddingBottom: spacing['2xl'] }}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={theme.colors.brand}
              colors={[theme.colors.brand]}
            />
          }
        >
          <Hero
            onSearch={submitSearch}
            onOpenFilters={() => openSearch({ browse: '1', openFilters: '1' })}
            onIntent={(listingType) => openSearch({ listingType })}
            onPostProperty={() => router.push('/owner/property/new')}
            onNotifications={() => router.push('/notifications')}
            onProfile={() => router.push('/profile')}
            notificationBadge={notificationBadge}
          />

          {/*
            NOT wrapped in `Reveal`, and it is the only row here that is not.

            `Reveal` exists to withhold a section's QUERY until it approaches
            the viewport, because every rail below is one of twenty requests a
            minute shared across a carrier NAT. This row makes no request — it
            replays a snapshot from disk — so there is nothing to defer, and
            deferring it would cost the one thing it is good at, which is being
            on screen the instant a returning user opens the app.
          */}
          <RecentlyViewed onSelectProperty={openProperty} />

          <Reveal placeholder={<SectionPlaceholder />}>
            <PopularListings
              onViewAll={openSearch}
              onSelectProperty={openProperty}
            />
          </Reveal>

          <Reveal placeholder={<SectionPlaceholder height={96} />}>
            <View className="pt-2xl">
              <TrustStrip />
            </View>
          </Reveal>

          <Reveal placeholder={<SectionPlaceholder />}>
            <BuilderProjects onSelectProject={openProject} onViewAll={() => router.push('/projects')} />
          </Reveal>

          {/*
            The editorial rails. Each is revealed separately, so its query
            fires only as it approaches the viewport — and each unmounts itself
            if it cannot meet its own `minResults`. See `HOME_COLLECTION_IDS`
            for why this is three rows and not the full registry of fifteen.
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

          {/*
            The research tools, between the inventory and the pitch. Housing's
            home carries six of these; we carry the two that have something
            behind them. `ToolsRow` explains both the placement and the count.
          */}
          <Reveal placeholder={<SectionPlaceholder height={220} />}>
            <Section
              title="Work out your budget"
              subtitle="Before you fall for something you cannot buy"
            >
              <ToolsRow onOpen={(route) => router.push(route)} />
            </Section>
          </Reveal>

          <Reveal placeholder={<SectionPlaceholder height={280} />}>
            <View className="pt-3xl">
              <AboutDealDirect />
            </View>
          </Reveal>

          <Reveal placeholder={<SectionPlaceholder height={300} />}>
            <Section title="Explore by City" subtitle="Every count below is live inventory">
              <CityGrid onSelect={(search) => openSearch({ search })} />
            </Section>
          </Reveal>

          <Reveal>
            <View className="pt-3xl">
              <CtaBanner onPress={() => openSearch({ browse: '1' })} />
            </View>
          </Reveal>
        </RevealScrollView>
    </View>
  );
}

/**
 * Most viewed.
 *
 * The subtitle changes with `isComplete`, and that is not decoration. While the
 * whole corpus fits in one page the ranking is genuinely the most-viewed
 * listings on DealDirect. Once it does not, the row is showing the most viewed
 * among the newest hundred, which is a weaker claim, and the copy stops making
 * the stronger one. See `usePopularListings`.
 */
function PopularListings({
  onViewAll,
  onSelectProperty,
}: {
  onViewAll: (params: PropertySearchParams & { browse?: string }) => void;
  onSelectProperty: (id: string) => void;
}) {
  const { items, isLoading, isComplete } = usePopularListings();

  if (!isLoading && items.length === 0) return null;

  return (
    <Section
      title="Popular Listings"
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
 * ranking invented here.
 *
 * This is also the only surface in the app where builder inventory appears at
 * all: `/properties/search` excludes builder-posted listings by design.
 */
function BuilderProjects({
  onSelectProject,
  onViewAll,
}: {
  onSelectProject: (id: string) => void;
  onViewAll: () => void;
}) {
  const { items, isLoading, total } = useRecentProjects();

  if (!isLoading && items.length === 0) return null;

  return (
    <Section
      title="Builder Projects"
      subtitle="New developments, direct from the builder"
      // Only offer "View all" when there is more than the rail already shows.
      // A link to a screen holding the same five cards is a dead end wearing a
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
 * Occupies roughly the height of a real section while unrevealed, so sections
 * below do not slide upward as each one loads and drag the content the user is
 * reading out from under them.
 */
function SectionPlaceholder({ height = 320 }: { height?: number }) {
  return <View style={{ height }} />;
}
