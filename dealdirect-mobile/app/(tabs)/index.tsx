import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { RefreshControl, View } from 'react-native';

import { qk } from '@/api';
import {
  AboutDealDirect,
  CityGrid,
  CtaBanner,
  Hero,
  Section,
  usePopularListings,
} from '@/features/home';
import { useNotifications } from '@/features/notifications';
import { PropertyRail, type ListingIntent } from '@/features/properties';
import { ProjectRail, useRecentProjects } from '@/features/projects';
import { Reveal, RevealScrollView } from '@/lib';
import { spacing, useTheme } from '@/theme';
import type { PropertySearchParams } from '@/types/backend/property';

/**
 * Home: discovery, not browsing.
 *
 *   Hero              full-bleed photograph, greeting, search, Buy/Rent/Post
 *   Popular Listings  ranked by view count
 *   Builder Projects  newest builder developments
 *   Why DealDirect    the pitch, once, in three lines
 *   Explore by City   live counts
 *   CTA
 *
 * Nothing here paginates and nothing here filters. Every affordance routes to
 * the one canonical results screen with a filter prefilled, so the app has a
 * single infinite scroll, a single filter sheet and a single sort.
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
 * THE COLLECTIONS ENGINE IS STILL HERE, JUST NOT RENDERED
 *
 * `features/home/collections.ts` holds fifteen curated rails (Luxury, Starter
 * Homes, Sea View and so on), each gated on live result counts. This layout
 * does not use them. They are one `COLLECTIONS.map()` away if the magazine
 * treatment is wanted later, and the registry costs nothing sitting idle.
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

  const openSearch = useCallback(
    (params?: PropertySearchParams & { search?: string; listingType?: ListingIntent }) => {
      router.push({ pathname: '/search', params: (params ?? {}) as Record<string, string> });
    },
    [router]
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
          onSearch={() => openSearch()}
          onIntent={(listingType) => openSearch({ listingType })}
          onPostProperty={() => router.push('/owner/property/new')}
          onNotifications={() => router.push('/notifications')}
          onProfile={() => router.push('/profile')}
          notificationBadge={notificationBadge}
        />

        <Reveal placeholder={<SectionPlaceholder />}>
          <PopularListings onViewAll={openSearch} onSelectProperty={openProperty} />
        </Reveal>

        <Reveal placeholder={<SectionPlaceholder />}>
          <BuilderProjects onSelectProject={openProject} onViewAll={() => router.push('/projects')} />
        </Reveal>

        <Reveal placeholder={<SectionPlaceholder height={280} />}>
          <View className="pt-2xl">
            <AboutDealDirect />
          </View>
        </Reveal>

        <Reveal placeholder={<SectionPlaceholder height={300} />}>
          <Section title="Explore by City" subtitle="Every count below is live inventory">
            <CityGrid onSelect={(search) => openSearch({ search })} />
          </Section>
        </Reveal>

        <Reveal>
          <CtaBanner onPress={() => openSearch()} />
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
  onViewAll: (params: PropertySearchParams) => void;
  onSelectProperty: (id: string) => void;
}) {
  const { items, isLoading, isComplete } = usePopularListings();

  if (!isLoading && items.length === 0) return null;

  return (
    <Section
      title="Popular Listings"
      subtitle={isComplete ? 'The most viewed homes right now' : 'Most viewed among our newest listings'}
      actionLabel="View all"
      onAction={() => onViewAll({ sort: 'newest' })}
    >
      <PropertyRail
        items={items}
        loading={isLoading}
        onSelect={onSelectProperty}
        accessibilityLabel="Popular listings"
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
