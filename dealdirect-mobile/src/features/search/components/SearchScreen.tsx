import { track } from '@/analytics';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { View } from 'react-native';

import Ionicons from '@expo/vector-icons/Ionicons';
import {
  LeafletMap,
  PropertyList,
  mapAvailable,
  type ListingIntent,
  type MapMarker,
  type PropertySummary,
} from '@/features/properties';
import { EnquirySheet, useSaveToggle } from '@/features/saved';
import { SaveSearchSheet } from '@/features/savedSearches';
import { gesture, radius, spacing, tabBarClearance, useTheme } from '@/theme';
import type { PropertySuggestion } from '@/types/backend/property';
import { PressableScale, Screen, Text } from '@/ui';
import {
  CITY_OPTIONS,
  DEFAULT_FILTERS,
  findPriceBand,
  hasAnyCriteria,
  type SearchFilters,
} from '../filters';
import {
  RELATED_THRESHOLD,
  useCompareSelection,
  usePropertySearchFeed,
  useRecentSearches,
  useRelatedProperties,
  useSuggestions,
} from '../hooks';
import { applyUnderstanding, buildParseContext } from '../queryUnderstanding';
import { readResumableSearch, recordResumableSearch } from '../resume';
import { CompareBar } from './CompareBar';
import { CompareSheet } from './CompareSheet';
import { FilterSheet } from './FilterSheet';
import { FiltersButton, QuickFilterBar } from './QuickFilterBar';
import { RelatedProperties } from './RelatedProperties';
import { ResultsToolbar } from './ResultsToolbar';
import { SearchBar } from './SearchBar';
import { RecentSearches, SuggestionList } from './SuggestionList';

/**
 * The search engine: browse, search and filter the whole corpus.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A COMPONENT AND NOT A SCREEN FILE — moved 2026-08-24
 *
 * This was `app/(tabs)/properties.tsx`, a tab of its own sitting beside a Home
 * tab that fetched nothing and did nothing except route here. Two tabs for one
 * job, and the first one was a landing page.
 *
 * The screen is now mounted by `app/(tabs)/index.tsx` as the Search tab, and
 * lives here so that the route file stays a route file. Nothing about the
 * search behaviour changed in the move — the modes, the filters, compare, the
 * save-search sheet and the related fallback are the code that was there, and
 * the notes below are the notes that came with it.
 *
 * ---------------------------------------------------------------------------
 * Renamed from "Search" 2026-08-14 (and back again 2026-08-24). The old name
 * described the ACT rather than the destination, which is why it read oddly in
 * the tab bar next to Home, Saved and Profile: three nouns and a verb. That
 * objection died with the Home tab — beside Activity, Updates and Profile,
 * Search is what this tab is for.
 *
 * Two modes on one screen, and the mode is explicit rather than inferred:
 *
 *   editing  — the field has focus and the suggestion panel is up.
 *   results  — the list is live.
 *
 * Inferring the mode from "is the field empty" is the usual shortcut and it
 * breaks the moment the user taps back into a field that already holds their
 * last query, wiping the results they were reading.
 *
 * ---------------------------------------------------------------------------
 * THE TAB OPENS ON RESULTS, NOT ON A PROMPT — fixed 2026-08-15
 *
 * Reported as "no properties are visible on the All filter", and it was worse
 * than that: on a fresh install this screen opened completely BLANK below the
 * search field. It started in `editing` with an empty field, which renders the
 * recent-searches panel, and that panel returns `null` when there are no
 * recent searches — which is every user's first visit.
 *
 * Two changes, and the second is the one that makes the class of bug go away:
 *
 *  1. The screen opens in results mode. `/properties/search` with no criteria
 *     returns the whole corpus, sorted and paginated, so "browse everything"
 *     is a real answer rather than the absence of one. A `browsing` flag used
 *     to carry that distinction; it is gone, because with no way to reach a
 *     criteria-less non-answer there is nothing left for it to distinguish.
 *  2. Editing mode only TAKES OVER the screen when it has something to put
 *     there. Focusing the field with nothing typed and no history now leaves
 *     the results in place instead of covering them with nothing.
 *
 * The old `StartPrompt` went with it. It existed to be shown when there was no
 * query to run, and there is no such state now.
 *
 * Typing still costs at most one debounced suggestions call, which matters
 * because both endpoints share a 20-request-per-minute limiter keyed on IP.
 */
export function SearchScreen() {
  const route = useLocalSearchParams<{
    search?: string;
    listingType?: string;
    sort?: string;
    /** A `PriceBand.id`. The affordability tool is the only caller — it turns a
     *  computed budget into the band containing it and hands it over, which is
     *  what makes that screen end in a search rather than in a figure. */
    priceBand?: string;
    /** A `City.id` from `features/home/cities.ts`, NOT a raw city name. The
     *  saved-search rows are the only caller; see the note on `run` there for
     *  why the id rather than the string the search was saved with. */
    city?: string;
    /** `'1'` from affordances that mean "show me everything", like a
     *  collection rail's "View all". Carries no criteria of its own. */
    browse?: string;
    /** `'1'` when the caller wants the filter sheet open on arrival. */
    openFilters?: string;
    /**
     * `'1'` from Home's "Continue your search" card.
     *
     * The stored search is read from the store rather than serialised through
     * the query string, because four of its filters are client-only and this
     * screen has never accepted them as params. Passing an id would be the
     * tidier shape and there is nothing to key it by: there is exactly one
     * resumable search. See `../resume.ts`.
     */
    resume?: string;
  }>();

  const [input, setInput] = useState('');
  const [filters, setFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  /** False on arrival: the tab opens on the whole corpus. See the module doc. */
  const [editing, setEditing] = useState(false);
  /**
   * Card or compact row. Screen-local rather than persisted: it is a reading
   * preference for the current search, and a user who switched to compact to
   * scan forty rentals does not necessarily want compact next time they open
   * a single saved listing.
   */
  const [density, setDensity] = useState<'card' | 'row'>('card');
  /**
   * List or map. A property search is two views of one result set, and which
   * one you want depends on whether you are scanning specs or judging where
   * things are. The toggle is a peer control, not a mode buried in a menu.
   *
   * Compare is a card-only interaction, so entering map mode leaves it; the
   * two cannot both own the screen.
   */
  const [mapMode, setMapMode] = useState(false);
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  const [saveSheetOpen, setSaveSheetOpen] = useState(false);
  const [compareSheetOpen, setCompareSheetOpen] = useState(false);
  /**
   * Compare is a MODE now, off by default.
   *
   * It used to be permanently on: every card carried an unlabelled circle in
   * the corner where a save control belongs, for a feature most sessions never
   * use. Common path on the surface, rare path one deliberate step deeper —
   * the toolbar's toggle is the step. Leaving the mode clears the selection,
   * because a selection you cannot see is a selection you will be surprised by.
   */
  const [comparing, setComparing] = useState(false);
  const compare = useCompareSelection();
  const save = useSaveToggle();

  /**
   * Filters arriving by route param.
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
    // Resume takes the whole stored filter set and ignores every other param,
    // because the two cannot both be the source of truth and the card is the
    // more specific request.
    if (route.resume === '1') {
      const stored = readResumableSearch();
      if (stored) {
        const key = `resume:${stored.savedAt}`;
        if (appliedRouteKey.current === key) return;
        appliedRouteKey.current = key;
        setFilters(stored.filters);
        setInput(stored.filters.query);
        setEditing(false);
        return;
      }
    }

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
    // Validated against the table for the same reason as `sort` and
    // `priceBand`: an id matching no city would set a client-side filter that
    // excludes every listing, on a screen with no visible control saying why.
    const city = CITY_OPTIONS.find((option) => option.value === route.city)?.value;

    // Nothing at all means the user tapped the tab directly, which must leave
    // their existing search alone.
    if (!search && !listingType && !sort && !browse && !priceBand && !city) return;

    const key = `${search ?? ''}|${listingType ?? ''}|${sort ?? ''}|${priceBand ?? ''}|${city ?? ''}|${browse ? '1' : ''}`;
    if (appliedRouteKey.current === key) return;
    appliedRouteKey.current = key;

    setInput(search ?? '');

    /*
      A search arriving by ROUTE is parsed, exactly as a typed one is.

      It used to be stored as raw text, which is why arriving from Home's hero
      with "1 bhk in mumbai" showed the unfiltered corpus and typing the same
      words into the field here immediately fixed it: `commit` ran the parse and
      this did not. One query, two behaviours, decided by how the user got here.

      The route's own params are the BASE rather than an overlay, so an explicit
      `listingType` or `city` from the caller still wins over the same thing
      inferred from the text — `applyUnderstanding` only fills what is unset.

      The context is empty because this runs on arrival, before any results have
      been seen. City, BHK, price and type do not need the corpus; an unresolved
      locality name degrades to a text match, which is what the raw-text
      behaviour did for every query.
    */
    const base: SearchFilters = {
      ...DEFAULT_FILTERS,
      query: search ?? '',
      listingType,
      priceBand,
      city,
      sort: sort ?? DEFAULT_FILTERS.sort,
    };

    setFilters(
      search ? applyUnderstanding(search, base, buildParseContext([])).filters : base
    );
    setEditing(false);
    if (route.openFilters === '1') setFilterSheetOpen(true);
  }, [
    route.search,
    route.listingType,
    route.sort,
    route.priceBand,
    route.city,
    route.browse,
    route.openFilters,
    route.resume,
  ]);

  const recent = useRecentSearches();
  const suggestions = useSuggestions(editing ? input : '');


  /**
   * Editing only covers the screen when the panel underneath has content —
   * suggestions for what is typed, or a search history to offer. Otherwise the
   * results stay visible behind the focused field, which is both more useful
   * and the thing that stops a blank screen being reachable at all.
   */
  const showEditingPanel = editing && (input.trim().length >= 2 || recent.items.length > 0);
  const showResults = !showEditingPanel;
  const feed = usePropertySearchFeed(filters, { enabled: showResults });

  // Offered once the direct match count is known and thin — never while the
  // first page is still loading, which would otherwise flash a "related" rail
  // for a result count that has not settled yet.
  const relatedEnabled =
    showResults && !feed.isInitialLoading && feed.items.length < RELATED_THRESHOLD;
  const relatedIds = useMemo(() => feed.items.map((item) => item.id), [feed.items]);
  const related = useRelatedProperties(filters, relatedIds, relatedEnabled);

  /**
   * The current results as map markers, dropping any without a real
   * coordinate — the adapter already nulls a (0,0) pin, so a filtered item is
   * genuinely unmappable rather than merely at the origin.
   */
  const mapMarkers = useMemo<MapMarker[]>(
    () =>
      feed.items
        .filter((item): item is PropertySummary & { coordinates: NonNullable<PropertySummary['coordinates']> } =>
          item.coordinates != null
        )
        .map((item) => ({
          id: item.id,
          lat: item.coordinates.lat,
          lng: item.coordinates.lng,
          price: item.priceRupees,
          intent: item.intent,
          title: item.headline ?? item.title,
          locationLabel: item.locationLabel,
        })),
    [feed.items]
  );

  const router = useRouter();
  const openProperty = useCallback((id: string) => router.push(`/property/${id}`), [router]);

  /**
   * The vocabulary the parser resolves place names against.
   *
   * Built from listings already in hand, never hard-coded: a locality absent
   * from the data must NOT become a filter, because that filter empties the
   * screen for inventory the user cannot tell is missing. With no corpus yet,
   * no locality is ever structured, which degrades to the old behaviour rather
   * than to a wrong one.
   *
   * ACCUMULATED rather than derived from the current page, and that is the
   * point: `feed.items` narrows as the user filters, so a context rebuilt from
   * it would forget "bandra" the moment a search excluded Bandra — and the next
   * query naming it would stop resolving. The set only ever grows within a
   * session.
   */
  const [knownLocalities, setKnownLocalities] = useState<string[]>([]);

  useEffect(() => {
    setKnownLocalities((current) => {
      const known = new Set(current);
      const before = known.size;

      for (const item of [...feed.items, ...related.items]) {
        const value = (item.locality ?? '').toLowerCase().replace(/\s+/g, ' ').trim();
        if (value.length >= 3) known.add(value);
      }

      // Same array identity when nothing is new, so a page of results the
      // parser already knew about does not re-render the screen or rebuild the
      // context below.
      return known.size === before ? current : [...known];
    });
  }, [feed.items, related.items]);

  const parseContext = useMemo(
    () => buildParseContext(knownLocalities.map((locality) => ({ locality }))),
    [knownLocalities]
  );

  /**
   * True when nothing has been asked for — the tab as it opens, browsing the
   * whole corpus. Used only to decide whether the current filter set is worth
   * remembering for Home's "Continue your search" card; "everything, newest
   * first" is not.
   */
  const idle = !hasAnyCriteria(filters);
  const trackedSearchKey = useRef<string | null>(null);

  /**
   * Remember a search worth resuming, once it has an answer.
   *
   * Written after the feed settles rather than at the moment of the tap,
   * because the card is worth tapping only if it can say how much was there.
   * `recordResumableSearch` ignores criteria-less filter sets and no-op
   * rewrites, so this costs nothing on the browse-everything path and does not
   * keep renewing its own expiry while the user scrolls.
   */
  useEffect(() => {
    if (idle || feed.isInitialLoading) return;
    recordResumableSearch(filters, feed.total);
    // One `search` event per distinct filter set, once it has an answer. The
    // key is the same identity `recordResumableSearch` uses, so scrolling a
    // list for ten minutes (which changes nothing) reports nothing.
    const key = JSON.stringify(filters);
    if (trackedSearchKey.current === key) return;
    trackedSearchKey.current = key;
    track('search', { city: filters.city, listingType: filters.listingType, results: feed.total });
  }, [idle, filters, feed.isInitialLoading, feed.total]);

  const commit = useCallback(
    (term: string) => {
      const trimmed = term.trim();
      setInput(trimmed);

      if (trimmed.length >= 2) recent.add(trimmed);

      setFilters((current) => {
        // Empty means "show me everything", which is a real answer and needs no
        // parsing.
        if (!trimmed) return { ...current, query: '' };

        /*
          Parsed against the CLEARED filter set, not the live one.

          A typed query is a complete statement of what the user wants now. If
          it were layered on the previous search, yesterday's price band would
          silently survive into today's query and there would be no visible
          control explaining why the results look wrong. The sort is kept
          because it is a display preference rather than a criterion.
        */
        const base: SearchFilters = { ...DEFAULT_FILTERS, sort: current.sort };
        return applyUnderstanding(trimmed, base, parseContext).filters;
      });

      setEditing(false);
    },
    [recent, parseContext]
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

  /**
   * Back to everything, not back to nothing. Clearing used to drop the screen
   * into editing mode with no criteria, which is the state that rendered
   * blank; it now lands on the unfiltered corpus, which is what "clear" means
   * on a browse screen.
   */
  const clear = useCallback(() => {
    setInput('');
    setFilters(DEFAULT_FILTERS);
    setEditing(false);
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

  const getSaveProps = useCallback(
    (item: PropertySummary) => ({
      saved: save.isSaved(item.id),
      busy: save.isBusy(item.id),
      onToggle: () => save.toggle(item),
    }),
    [save]
  );

  const toggleCompareMode = useCallback(() => {
    setComparing((current) => {
      if (current) {
        compare.clear();
        return false;
      }
      // Compare selection lives on the card's photo corner, and the compact
      // row has no free corner to put it in. Entering the mode from the row
      // view therefore switches back to cards rather than lighting the toggle
      // over a list with no checkboxes on it — a mode that is on and has no
      // visible effect is the worst version of a mode.
      setDensity('card');
      return true;
    });
  }, [compare]);

  return (
    <Screen edges={['top']}>
      {/*
        The search row is inset; the rail below it is NOT, and that difference
        is deliberate. A horizontally scrolling strip inside a padded container
        is clipped 16pt short of each screen edge, so its pills stop and start
        in mid-air rather than sliding off the side. Every portal's filter rail
        runs edge to edge for the same reason. The rail draws its own fade at
        the right edge so the pill under it reads as continuing rather than as
        chopped — see `QuickFilterBar`.
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

          {/* Cancel while the panel is up, Filters otherwise. They never both
              apply: the panel covers the list, and there is nothing to filter
              while you cannot see it. */}
          {showEditingPanel ? (
            <PressableScale
              accessibilityRole="button"
              accessibilityLabel="Back to results"
              hitSlop={gesture.hitSlop}
              onPress={() => {
                setInput(filters.query);
                setEditing(false);
              }}
            >
              <Text variant="callout" tone="accent">
                Cancel
              </Text>
            </PressableScale>
          ) : (
            <FiltersButton filters={filters} onPress={() => setFilterSheetOpen(true)} />
          )}
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

        Filters left the rail on 2026-08-15 and now sits beside the search field
        above. It opens a surface rather than setting a value, so it belongs
        with the screen's other control, and moving it gave the rail back 93pt —
        enough that the segmented control and two facet pills are legible before
        anyone scrolls.
      */}
      <View className="pb-sm pt-md">
        <QuickFilterBar filters={filters} onChange={applyFilters} />
      </View>

      {showEditingPanel ? (
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
      ) : mapMode && mapAvailable ? (
        <SearchMapView
          markers={mapMarkers}
          total={feed.total}
          loading={feed.isInitialLoading}
          onOpen={openProperty}
          onExit={() => setMapMode(false)}
        />
      ) : (
        <PropertyList
          feed={feed}
          header={
            feed.total > 0 ? (
              <ResultsToolbar
                total={feed.total}
                density={density}
                onToggleDensity={() =>
                  setDensity((current) => (current === 'card' ? 'row' : 'card'))
                }
                comparing={comparing}
                compareCount={compare.items.length}
                onToggleCompare={toggleCompareMode}
                onSaveSearch={() => setSaveSheetOpen(true)}
                // Switching density while comparing would strand the selection
                // on a view that cannot show it, so the control leaves with the
                // mode rather than being disabled inside it.
                showDensity={!comparing}
                // The map toggle only appears where the WebView exists and the
                // user is not mid-compare, which is a card-only interaction.
                onToggleMap={mapAvailable && !comparing ? () => setMapMode(true) : undefined}
              />
            ) : undefined
          }
          emptyTitle="No matches"
          emptyDescription="Try fewer filters, or search a nearby city or locality instead."
          emptyActionLabel="Clear search"
          onEmptyAction={clear}
          footer={<RelatedProperties items={related.items} />}
          getSaveProps={getSaveProps}
          // Compare selection is a card-only affordance: the compact row has no
          // free corner, and comparing is a considered act that belongs with the
          // photo you are considering.
          getCompareProps={comparing && density === 'card' ? getCompareProps : undefined}
          density={density}
        />
      )}

      {showResults ? (
        <CompareBar
          active={comparing}
          items={compare.items}
          onRemove={(id) => {
            const item = compare.items.find((i) => i.id === id);
            if (item) compare.toggle(item);
          }}
          onClear={compare.clear}
          onCompare={() => setCompareSheetOpen(true)}
          onExit={toggleCompareMode}
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

      {/* States what an enquiry does before it is sent — see `EnquirySheet`. */}
      <EnquirySheet
        visible={save.pending !== null}
        subtitle={save.pending?.locationLabel || save.pending?.title}
        remaining={save.remaining}
        onConfirm={save.confirm}
        onCancel={save.cancel}
      />
    </Screen>
  );
}

/** Accepted `sort` route params. Anything else is ignored rather than trusted. */
const SORT_VALUES = ['newest', 'priceAsc', 'priceDesc'] as const;

/**
 * The results, as a map.
 *
 * Full-bleed under the search row, with a floating "List" pill to return. It
 * plots the markers it is given and says so honestly when a search has results
 * the map cannot place: a large share of the corpus carries no coordinate, so
 * "12 results, 3 on the map" is a real state the user must not mistake for the
 * map being broken.
 */
function SearchMapView({
  markers,
  total,
  loading,
  onOpen,
  onExit,
}: {
  markers: MapMarker[];
  total: number;
  loading: boolean;
  onOpen: (id: string) => void;
  onExit: () => void;
}) {
  const theme = useTheme();

  return (
    <View style={{ flex: 1 }}>
      {markers.length === 0 ? (
        <View className="flex-1 items-center justify-center px-xl" style={{ gap: spacing.base }}>
          <Ionicons name="map-outline" size={40} color={theme.colors.textMuted} />
          <Text variant="body" tone="secondary" className="text-center">
            {loading
              ? 'Loading the map…'
              : total > 0
                ? 'None of these listings have a pinned location yet.'
                : 'No results to map.'}
          </Text>
        </View>
      ) : (
        <LeafletMap markers={markers} mode="search" fitOnReady onViewDetails={onOpen} />
      )}

      {/* The count the map can actually show, stated plainly when it differs
          from the result total. */}
      {markers.length > 0 && markers.length < total ? (
        <View
          pointerEvents="none"
          style={{
            position: 'absolute',
            top: spacing.md,
            alignSelf: 'center',
            paddingHorizontal: spacing.base,
            paddingVertical: spacing.xs,
            borderRadius: radius.full,
            backgroundColor: theme.colors.surface,
            borderWidth: 1,
            borderColor: theme.colors.border,
          }}
        >
          <Text variant="caption" tone="secondary">
            {markers.length} of {total} on the map
          </Text>
        </View>
      ) : null}

      <PressableScale
        accessibilityRole="button"
        accessibilityLabel="Back to list"
        onPress={onExit}
        activeScale={0.96}
        style={{
          position: 'absolute',
          bottom: tabBarClearance + spacing.base,
          alignSelf: 'center',
          flexDirection: 'row',
          alignItems: 'center',
          gap: spacing.sm,
          paddingHorizontal: spacing.lg,
          height: 44,
          borderRadius: radius.full,
          backgroundColor: theme.colors.brand,
          shadowColor: '#000',
          shadowOpacity: 0.2,
          shadowRadius: 10,
          shadowOffset: { width: 0, height: 4 },
          elevation: 8,
        }}
      >
        <Ionicons name="list" size={18} color={theme.colors.textOnAccent} />
        <Text variant="callout" style={{ color: theme.colors.textOnAccent, fontWeight: '700' }}>
          List
        </Text>
      </PressableScale>
    </View>
  );
}
