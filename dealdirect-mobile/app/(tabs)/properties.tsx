import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Pressable, View } from 'react-native';

import { PropertyList, type ListingIntent, type PropertySummary } from '@/features/properties';
import {
  CompareBar,
  CompareSheet,
  DEFAULT_FILTERS,
  FilterSheet,
  QuickFilterBar,
  RecentSearches,
  RELATED_THRESHOLD,
  RelatedProperties,
  SearchBar,
  SuggestionList,
  findPriceBand,
  hasAnyCriteria,
  usePropertySearchFeed,
  useCompareSelection,
  useRecentSearches,
  useRelatedProperties,
  useSuggestions,
  type SearchFilters,
} from '@/features/search';
import { SaveSearchSheet } from '@/features/savedSearches';
import { gesture, radius, spacing, useTheme } from '@/theme';
import type { PropertySuggestion } from '@/types/backend/property';
import { Button, Screen, Text } from '@/ui';

/**
 * Properties — browse, search and filter the whole corpus.
 *
 * Renamed from "Search" 2026-08-14. The old name described the ACT rather than
 * the destination, which is why it read oddly in the tab bar next to Home,
 * Saved and Profile: three nouns and a verb. It also undersold the screen —
 * arriving from Home's "View all" or the CTA banner lands here with no query
 * at all, browsing everything, which is not searching.
 *
 * Two modes on one screen, and the mode is explicit rather than inferred:
 *
 *   editing  — the field has focus and the suggestion panel is up. Nothing is
 *              being fetched from `/search`.
 *   results  — a term or a filter has been committed, and the list is live.
 *
 * Inferring the mode from "is the field empty" is the usual shortcut and it
 * breaks the moment the user taps back into a field that already holds their
 * last query, wiping the results they were reading.
 *
 * Nothing here fires a property search until a term is committed. Typing costs
 * at most one debounced suggestions call, which matters because both endpoints
 * share a 20-request-per-minute limiter keyed on IP.
 */
export default function PropertiesScreen() {
  const route = useLocalSearchParams<{
    search?: string;
    listingType?: string;
    sort?: string;
    /** A `PriceBand.id`. The affordability tool is the only caller — it turns a
     *  computed budget into the band containing it and hands it over, which is
     *  what makes that screen end in a search rather than in a figure. */
    priceBand?: string;
    /** `'1'` from affordances that mean "show me everything", like Home's
     *  "View all" and the CTA banner. Carries no criteria of its own. */
    browse?: string;
    /** `'1'` when the caller wants the filter sheet open on arrival — the
     *  Home hero's filter control, which has nowhere of its own to show it. */
    openFilters?: string;
  }>();

  const [input, setInput] = useState('');
  const [filters, setFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [editing, setEditing] = useState(true);
  /**
   * Browse-everything mode.
   *
   * `/properties/search` is perfectly happy with no criteria — it returns the
   * whole corpus, sorted and paginated. So "show me everything" is a real
   * results state, not an absence of one. Without this flag `hasAnyCriteria`
   * is false and the screen falls through to `StartPrompt`, which is what made
   * Home's "View all" and CTA banner land on an empty screen.
   */
  const [browsing, setBrowsing] = useState(false);
  /**
   * Card or compact row. Screen-local rather than persisted: it is a reading
   * preference for the current search, and a user who switched to compact to
   * scan forty rentals does not necessarily want compact next time they open
   * a single saved listing.
   */
  const [density, setDensity] = useState<'card' | 'row'>('card');
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  const [saveSheetOpen, setSaveSheetOpen] = useState(false);
  const [compareSheetOpen, setCompareSheetOpen] = useState(false);
  const compare = useCompareSelection();

  /**
   * Filters arriving from Home.
   *
   * Applied per distinct navigation rather than on every render, keyed on the
   * params themselves. A tab screen stays mounted, so re-running this on each
   * render would fight the user: change the rent/sale control, re-render, and
   * the route params would immediately stamp the old value back over it.
   *
   * Tapping the Search tab directly carries no params, which correctly leaves
   * whatever the user last had.
   */
  const appliedRouteKey = useRef<string | null>(null);

  useEffect(() => {
    const search = typeof route.search === 'string' ? route.search : undefined;
    const listingType =
      route.listingType === 'rent' || route.listingType === 'sale'
        ? (route.listingType as ListingIntent)
        : undefined;
    const sort = SORT_VALUES.find((value) => value === route.sort);
    const browse = route.browse === '1';
    // Validated against the table rather than trusted, same rule as `sort`: a
    // band id that matches nothing would set a filter the sheet cannot show
    // and the user cannot clear.
    const priceBand = findPriceBand(route.priceBand)?.id;

    // Nothing at all means the user tapped the tab directly, which must leave
    // their existing search alone.
    if (!search && !listingType && !sort && !browse && !priceBand) return;

    const key = `${search ?? ''}|${listingType ?? ''}|${sort ?? ''}|${priceBand ?? ''}|${browse ? '1' : ''}`;
    if (appliedRouteKey.current === key) return;
    appliedRouteKey.current = key;

    setInput(search ?? '');
    setFilters({
      ...DEFAULT_FILTERS,
      query: search ?? '',
      listingType,
      priceBand,
      sort: sort ?? DEFAULT_FILTERS.sort,
    });
    setBrowsing(browse);
    setEditing(false);
    if (route.openFilters === '1') setFilterSheetOpen(true);
  }, [
    route.search,
    route.listingType,
    route.sort,
    route.priceBand,
    route.browse,
    route.openFilters,
  ]);

  const recent = useRecentSearches();
  const suggestions = useSuggestions(editing ? input : '');

  const showResults = !editing && (hasAnyCriteria(filters) || browsing);
  const feed = usePropertySearchFeed(filters, { enabled: showResults });

  // Offered once the direct match count is known and thin — never while the
  // first page is still loading, which would otherwise flash a "related" rail
  // for a result count that has not settled yet.
  const relatedEnabled =
    showResults && !feed.isInitialLoading && feed.items.length < RELATED_THRESHOLD;
  const relatedIds = useMemo(() => feed.items.map((item) => item.id), [feed.items]);
  const related = useRelatedProperties(filters, relatedIds, relatedEnabled);

  const commit = useCallback(
    (term: string) => {
      const trimmed = term.trim();
      setInput(trimmed);
      setFilters((current) => ({ ...current, query: trimmed }));
      if (trimmed.length >= 2) recent.add(trimmed);
      // Committing an empty field is "show me everything", not "show me
      // nothing" — the same state the Home CTA arrives in.
      setBrowsing(trimmed.length === 0);
      setEditing(false);
    },
    [recent]
  );

  /**
   * Every suggestion kind commits as free text.
   *
   * A `city` row could instead set the exact `city` param, but that would put
   * state in the query that the search field does not show, so a user clearing
   * the field would still be filtered by an invisible city. The `search` regex
   * already covers `address.city` and `address.area` case-insensitively, so the
   * result is the same and the state stays legible.
   */
  const selectSuggestion = useCallback(
    (suggestion: PropertySuggestion) => commit(suggestion.value),
    [commit]
  );

  const clear = useCallback(() => {
    setInput('');
    setFilters(DEFAULT_FILTERS);
    setBrowsing(false);
    setEditing(true);
  }, []);

  const applyFilters = useCallback((next: SearchFilters) => {
    setFilters(next);
    setFilterSheetOpen(false);
    setEditing(false);
  }, []);

  const getCompareProps = useCallback(
    (item: PropertySummary) => ({
      selected: compare.isSelected(item.id),
      disabled: !compare.canToggle(item),
      onToggle: () => compare.toggle(item),
    }),
    [compare]
  );

  return (
    <Screen edges={['top']}>
      {/*
        The search row is inset; the rail below it is NOT, and that difference
        is deliberate. A horizontally scrolling strip inside a padded container
        is clipped 16pt short of each screen edge, so its pills stop and start
        in mid-air rather than sliding off the side. Every portal's filter rail
        runs edge to edge for the same reason — the cut-off pill at the right
        margin is what says there is more to scroll to.
      */}
      <View className="px-base pt-sm">
        <View className="flex-row items-center gap-sm">
          <View className="flex-1">
            <SearchBar
              value={input}
              onChangeText={(value) => {
                setInput(value);
                setEditing(true);
              }}
              onFocus={() => setEditing(true)}
              onSubmit={() => commit(input)}
              onClear={clear}
            />
          </View>

          {/* Only offered when there are results to go back TO. Without it,
              tapping the field to check what you typed strands you in the
              suggestion panel with no way out but submitting again. */}
          {editing && (hasAnyCriteria(filters) || browsing) ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Back to results"
              hitSlop={gesture.hitSlop}
              onPress={() => {
                setInput(filters.query);
                setEditing(false);
              }}
              style={({ pressed }) => (pressed ? { opacity: 0.7 } : undefined)}
            >
              <Text variant="callout" tone="accent">
                Cancel
              </Text>
            </Pressable>
          ) : null}
        </View>
      </View>

      {/*
        THE QUICK-FILTER RAIL — 2026-08-14.

        This row used to be Filters plus three rent/sale chips, and every other
        facet was four taps deep behind Filters. It is now the pill rail the
        large portals run on their results pages; see `QuickFilterBar` for what
        was copied from which and why the three kinds of control on it look
        different.

        Still ONE row. The point of the earlier revision was that three stacked
        rows of chrome is most of a phone's viewport spent on how to look rather
        than on what there is, and adding six facets must not undo that — hence
        a rail that scrolls sideways rather than wraps.
      */}
      <View className="pb-md pt-md">
        <QuickFilterBar
          filters={filters}
          onChange={applyFilters}
          onOpenAllFilters={() => setFilterSheetOpen(true)}
        />
      </View>

      {editing ? (
        <View className="flex-1">
          {input.trim().length >= 2 ? (
            <SuggestionList
              suggestions={suggestions.items}
              isLoading={suggestions.isLoading}
              term={suggestions.term || input.trim()}
              onSelect={selectSuggestion}
            />
          ) : (
            <RecentSearches
              items={recent.items}
              onSelect={commit}
              onRemove={recent.remove}
              onClear={recent.clear}
            />
          )}
        </View>
      ) : showResults ? (
        <PropertyList
          feed={feed}
          header={
            feed.total > 0 ? (
              <ResultBar
                total={feed.total}
                density={density}
                onToggleDensity={() =>
                  setDensity((current) => (current === 'card' ? 'row' : 'card'))
                }
                onSaveSearch={() => setSaveSheetOpen(true)}
              />
            ) : undefined
          }
          emptyTitle="No matches"
          emptyDescription="Try fewer filters, or search a nearby city or locality instead."
          emptyActionLabel="Clear search"
          onEmptyAction={clear}
          footer={<RelatedProperties items={related.items} />}
          getCompareProps={density === 'card' ? getCompareProps : undefined}
          density={density}
        />
      ) : (
        <StartPrompt onBrowseAll={() => commit('')} />
      )}

      {showResults ? (
        <CompareBar
          items={compare.items}
          onRemove={(id) => {
            const item = compare.items.find((i) => i.id === id);
            if (item) compare.toggle(item);
          }}
          onClear={compare.clear}
          onCompare={() => setCompareSheetOpen(true)}
        />
      ) : null}

      <FilterSheet
        visible={filterSheetOpen}
        filters={filters}
        onClose={() => setFilterSheetOpen(false)}
        onApply={applyFilters}
      />

      <SaveSearchSheet
        visible={saveSheetOpen}
        onClose={() => setSaveSheetOpen(false)}
        seedTerm={filters.query}
      />

      <CompareSheet
        visible={compareSheetOpen}
        items={compare.items}
        onClose={() => setCompareSheetOpen(false)}
      />
    </Screen>
  );
}

/**
 * The result bar: how many, and the two controls that act on the whole set.
 *
 * ---------------------------------------------------------------------------
 * IT SCROLLS NOW — 2026-08-14.
 *
 * This used to be fixed chrome between the filter strip and the list. Adding
 * the quick-filter rail above it would have made the fixed chrome a search
 * field, a rail and this, which is around a fifth of a phone's viewport gone
 * before the first result — the exact problem the rail was collapsing three
 * rows into one to avoid.
 *
 * So it moved into the list as its header. That is not a demotion, it is the
 * correct place for it: the count and these two controls describe the ANSWER,
 * and an answer belongs with the results rather than with the question. The
 * search field and the rail are the question and they stay put, because those
 * are what a user reaches for while looking at a result they want to change.
 */
function ResultBar({
  total,
  density,
  onToggleDensity,
  onSaveSearch,
}: {
  total: number;
  density: 'card' | 'row';
  onToggleDensity: () => void;
  onSaveSearch: () => void;
}) {
  const theme = useTheme();

  return (
    <View className="flex-row items-center justify-between pb-sm">
      <Text variant="footnote" tone="secondary">
        {total.toLocaleString('en-IN')} {total === 1 ? 'property' : 'properties'}
      </Text>

      <View className="flex-row items-center" style={{ gap: spacing.xs }}>
        {/*
          Saving is offered only once there are results, because a saved
          search that matched nothing produces an alert the user cannot
          interpret. See `SaveSearchSheet` for why the term is saved as a
          NAME rather than as a filter.
        */}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Save this search"
          hitSlop={gesture.hitSlop}
          onPress={onSaveSearch}
          className="h-9 w-9 items-center justify-center rounded-full"
          style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
        >
          <Ionicons name="bookmark-outline" size={18} color={theme.colors.textSecondary} />
        </Pressable>

        {/*
          Density. Not decoration: the compact row fits about three times as
          many results per screen, which matters most to users on large
          accessibility text who see fewest. See `PropertyRow`.
        */}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={
            density === 'card' ? 'Switch to compact list' : 'Switch to large cards'
          }
          hitSlop={gesture.hitSlop}
          onPress={onToggleDensity}
          className="h-9 w-9 items-center justify-center rounded-full"
          style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
        >
          <Ionicons
            name={density === 'card' ? 'list-outline' : 'grid-outline'}
            size={19}
            color={theme.colors.textSecondary}
          />
        </Pressable>
      </View>
    </View>
  );
}

/** Accepted `sort` route params. Anything else is ignored rather than trusted. */
const SORT_VALUES = ['newest', 'priceAsc', 'priceDesc'] as const;

/**
 * Shown when the criteria were cleared to nothing, which leaves no query to
 * run.
 *
 * It offers a way OUT rather than only describing the state: the whole corpus
 * is one tap away, and an empty screen whose only instruction is "type
 * something" is a dead end for a user who does not yet know what to type.
 */
function StartPrompt({ onBrowseAll }: { onBrowseAll: () => void }) {
  const theme = useTheme();

  return (
    <View className="flex-1 items-center justify-center px-xl">
      <View
        style={{
          width: 72,
          height: 72,
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: radius.full,
          backgroundColor: theme.colors.brandMuted,
          marginBottom: spacing.lg,
        }}
      >
        <Ionicons name="home-outline" size={30} color={theme.colors.brand} />
      </View>

      <Text variant="title3" className="text-center">
        Find your place
      </Text>
      <Text variant="callout" tone="secondary" className="mt-sm text-center">
        Search a city, locality or project — or browse everything on
        DealDirect right now.
      </Text>

      <Button
        label="Browse all properties"
        align="center"
        className="mt-xl"
        onPress={onBrowseAll}
      />
    </View>
  );
}
