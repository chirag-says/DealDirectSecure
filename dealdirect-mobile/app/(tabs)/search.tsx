import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { PropertyList, usePropertyFeed, type ListingIntent } from '@/features/properties';
import {
  DEFAULT_FILTERS,
  FilterSheet,
  LISTING_TYPE_OPTIONS,
  RecentSearches,
  SearchBar,
  SuggestionList,
  countActiveFilters,
  hasAnyCriteria,
  toSearchParams,
  useRecentSearches,
  useSuggestions,
  type SearchFilters,
} from '@/features/search';
import { gesture, useTheme } from '@/theme';
import type { PropertySuggestion } from '@/types/backend/property';
import { Screen, Text } from '@/ui';

/**
 * Search.
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
export default function SearchScreen() {
  const theme = useTheme();
  const route = useLocalSearchParams<{ search?: string; listingType?: string }>();

  const [input, setInput] = useState('');
  const [filters, setFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [editing, setEditing] = useState(true);
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);

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

    if (!search && !listingType) return;

    const key = `${search ?? ''}|${listingType ?? ''}`;
    if (appliedRouteKey.current === key) return;
    appliedRouteKey.current = key;

    setInput(search ?? '');
    setFilters({ ...DEFAULT_FILTERS, query: search ?? '', listingType });
    setEditing(false);
  }, [route.search, route.listingType]);

  const recent = useRecentSearches();
  const suggestions = useSuggestions(editing ? input : '');

  const params = useMemo(() => toSearchParams(filters), [filters]);
  const showResults = !editing && hasAnyCriteria(filters);
  const feed = usePropertyFeed(params, { enabled: showResults });

  const commit = useCallback(
    (term: string) => {
      const trimmed = term.trim();
      setInput(trimmed);
      setFilters((current) => ({ ...current, query: trimmed }));
      if (trimmed.length >= 2) recent.add(trimmed);
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
    setEditing(true);
  }, []);

  const applyFilters = useCallback((next: SearchFilters) => {
    setFilters(next);
    setFilterSheetOpen(false);
    setEditing(false);
  }, []);

  const activeCount = countActiveFilters(filters);

  return (
    <Screen>
      <View className="gap-md px-base pb-md pt-sm">
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
          {editing && hasAnyCriteria(filters) ? (
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

        {/*
          The filter control is a real bordered target, not floating icon+text.
          Bare coloured text next to a result count reads as a label rather than
          a button, and it was the only tappable thing on the row with nothing
          to say so. When filters are on, the control fills instead of growing a
          separate count badge: one element carrying the state beats two.
        */}
        <View className="flex-row items-center justify-between">
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ selected: activeCount > 0 }}
            accessibilityLabel={activeCount > 0 ? `Filters, ${activeCount} applied` : 'Filters'}
            hitSlop={gesture.hitSlop}
            onPress={() => setFilterSheetOpen(true)}
            className={[
              'flex-row items-center rounded-full border px-md py-sm',
              activeCount > 0 ? 'border-accent bg-accent-muted' : 'border-border',
            ].join(' ')}
            style={({ pressed }) => (pressed ? { opacity: 0.7 } : undefined)}
          >
            <Ionicons
              name="options-outline"
              size={16}
              color={activeCount > 0 ? theme.colors.accent : theme.colors.textSecondary}
            />
            <Text
              variant={activeCount > 0 ? 'bodyEmphasis' : 'callout'}
              tone={activeCount > 0 ? 'accent' : 'secondary'}
              className="ml-xs"
            >
              {activeCount > 0 ? `Filters · ${activeCount}` : 'Filters'}
            </Text>
          </Pressable>

          {showResults && feed.total > 0 ? (
            <Text variant="footnote" tone="muted">
              {feed.total.toLocaleString('en-IN')} results
            </Text>
          ) : null}
        </View>

        {/*
          Rent versus sale stays permanently visible rather than living in the
          sheet. It is the primary axis of a property search and it is what the
          Home cards preselect, so a user who arrived via "For Rent" has to be
          able to see that is why they are seeing rentals, and change it in one
          tap rather than opening a sheet to find out.
        */}
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={INTENT_ROW_STYLE}
        >
          {LISTING_TYPE_OPTIONS.map((option) => {
            const selected = filters.listingType === option.value;
            return (
              <Pressable
                key={option.label}
                accessibilityRole="button"
                accessibilityState={{ selected }}
                onPress={() => {
                  setFilters((current) => ({ ...current, listingType: option.value }));
                  setEditing(false);
                }}
                style={({ pressed }) => (pressed ? { opacity: 0.75 } : undefined)}
                className={[
                  'rounded-full border px-md py-sm',
                  selected ? 'border-accent bg-accent-muted' : 'border-border',
                ].join(' ')}
              >
                <Text
                  variant={selected ? 'bodyEmphasis' : 'callout'}
                  tone={selected ? 'accent' : 'secondary'}
                >
                  {option.label}
                </Text>
              </Pressable>
            );
          })}
        </ScrollView>
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
          emptyTitle="No matches"
          emptyDescription="Try fewer filters, or search a nearby city or locality instead."
          emptyActionLabel="Clear search"
          onEmptyAction={clear}
        />
      ) : (
        <StartPrompt />
      )}

      <FilterSheet
        visible={filterSheetOpen}
        filters={filters}
        onClose={() => setFilterSheetOpen(false)}
        onApply={applyFilters}
      />
    </Screen>
  );
}

const INTENT_ROW_STYLE = { gap: 8 } as const;

/** Shown when the criteria were cleared to nothing, which leaves no query to run. */
function StartPrompt() {
  const theme = useTheme();

  return (
    <View className="flex-1 items-center justify-center px-xl">
      <Ionicons name="search-outline" size={32} color={theme.colors.textMuted} />
      <Text variant="title3" className="mt-base text-center">
        Search properties
      </Text>
      <Text variant="callout" tone="secondary" className="mt-sm text-center">
        Type a city, locality or project name, or open filters to browse by
        property type.
      </Text>
    </View>
  );
}
