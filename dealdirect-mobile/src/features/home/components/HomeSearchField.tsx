import Ionicons from '@expo/vector-icons/Ionicons';
import { useRef, useState, type ReactNode } from 'react';
import { Pressable, TextInput, View } from 'react-native';

import { PropertyListItem } from '@/features/properties';
import { RecentSearches, useRecentSearches, useSearchPreview } from '@/features/search';
import { gesture, radius, spacing, useTheme } from '@/theme';
import { PressableScale, Skeleton, Text, useTextInputStyle } from '@/ui';
import type { City } from '../cities';
import {
  HERO_SEARCH_BLUE,
  HERO_SEARCH_GAP_PX,
  HERO_SEARCH_INK,
  HERO_SEARCH_PILL_PX,
  HERO_SEARCH_PLACEHOLDER,
  useMockScale,
} from '../heroTheme';

/**
 * The hero's search field — a real input that answers with real listings.
 *
 * ---------------------------------------------------------------------------
 * WHY IT NO LONGER JUST JUMPS TO THE SEARCH TAB
 *
 * This used to be a button dressed as a search box: tapping it anywhere
 * navigated straight to the Search screen, so the field on Home was a decoy
 * for the real one a tab away. A person who taps a search box expects to type
 * into it, not to change screens.
 *
 * Now they type here and see MATCHES as they go, and the screen only CHANGES
 * on a deliberate search: the search button, the keyboard's search key, or a
 * result tap. Focusing the field and typing keep the user on Home.
 *
 * ---------------------------------------------------------------------------
 * THE DROPDOWN SHOWS RESULTS, NOT NAME-AUTOCOMPLETE — fixed 2026-08-24
 *
 * The first version fed the dropdown from `useSuggestions`, which autocompletes
 * place and project NAMES. A natural-language query — "1 bhk in mumbai" — has
 * no name to match, so the panel said "no matches" while the Search tab, which
 * PARSES the query into a 1 BHK + Mumbai filter, found the listing. Two answers
 * to the same question, and the wrong one was on the screen the user starts on.
 *
 * `useSearchPreview` runs the real, parsed search and this panel shows the top
 * few as the same cards the results list uses. "See all" hands the whole query
 * to the Search tab for pagination, filters and sort.
 *
 * ---------------------------------------------------------------------------
 * THE PANEL IS RENDERED INLINE, NOT AS A FLOATING DROPDOWN
 *
 * It sits in the hero's own column and grows the block downward while focused,
 * rather than floating over the content below on an absolute layer that would
 * fight the scroll for its anchor. Capped at a handful of rows so it never
 * needs a scroll view of its own nested inside Home's.
 */

/** How many preview rows show before the panel would need to scroll. Matches
 *  `useSearchPreview`'s own ceiling. */
const MAX_PREVIEW_ROWS = 6;

export interface HomeSearchFieldProps {
  /** The scoped city, for the placeholder. The redirect adds the filter. */
  city: City | null;
  /**
   * The query text, owned by the screen.
   *
   * CONTROLLED because Home renders this twice — once in the hero and once in
   * the pinned header — and they are one field as far as the user is concerned.
   * Local text state would strand what was typed in the hero the moment the
   * header's copy took over at the pin.
   */
  value: string;
  onChangeText: (value: string) => void;
  /**
   * Run a search. Empty term means "browse everything". The caller owns the
   * navigation and rides the selected city along; this component only decides
   * WHEN a search is deliberate enough to leave Home for.
   */
  onSubmit: (term: string) => void;
  /** Open a previewed listing directly, without going through the results list. */
  onOpenProperty: (id: string) => void;
  /** Reported so the pinned header can hold itself open while the panel is up. */
  onFocusChange?: (focused: boolean) => void;
  /**
   * Drop the leading margin. The header's pinned copy has to start at its
   * container's very top edge, because that edge is where the hero's copy
   * arrives — see the handover note in `HomeHeader`.
   */
  flush?: boolean;
}

export function HomeSearchField({
  city,
  value,
  onChangeText,
  onSubmit,
  onOpenProperty,
  onFocusChange,
  flush = false,
}: HomeSearchFieldProps) {
  const theme = useTheme();
  const inputStyle = useTextInputStyle();
  const inputRef = useRef<TextInput>(null);

  const query = value;
  const setQuery = onChangeText;
  const [focused, setFocusedState] = useState(false);

  const setFocused = (next: boolean) => {
    setFocusedState(next);
    onFocusChange?.(next);
  };

  const recent = useRecentSearches();
  // Only queried while focused, so a blurred field with stale text fires
  // nothing. The hook's own debounce and two-char floor guard the limiter.
  const preview = useSearchPreview(focused ? query : '');

  const trimmed = query.trim();
  const typing = trimmed.length >= 2;
  const showPanel = focused && (typing || (trimmed.length === 0 && recent.items.length > 0));

  const submit = (term: string) => {
    const value = term.trim();
    if (value.length >= 2) recent.add(value);
    inputRef.current?.blur();
    setFocused(false);
    onSubmit(value);
  };

  const openProperty = (id: string) => {
    inputRef.current?.blur();
    setFocused(false);
    onOpenProperty(id);
  };

  const mockPx = useMockScale();
  const placeholder = city ? `Search in ${city.label}` : 'Search locality, project or city';
  const previewItems = preview.items.slice(0, MAX_PREVIEW_ROWS);
  const more = Math.max(preview.total - previewItems.length, 0);

  return (
    <View style={{ marginTop: flush ? 0 : mockPx(HERO_SEARCH_GAP_PX) }}>
      {/* The search pill, to the reference (measured pass): a white pill 86
          tall with the glyph 30 from its left edge, and the blue submit — an
          84 circle — INSIDE the pill's right end, one pixel in from its edge.
          It used to hang 28 beyond the pill, which read as the button drifting
          off to the right (2026-09-06). Same input, same handlers, same
          submit; only the dress changed. */}
      <View style={{ height: mockPx(HERO_SEARCH_PILL_PX), justifyContent: 'center' }}>
        <View
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            flexDirection: 'row',
            alignItems: 'center',
            gap: mockPx(24),
            paddingLeft: mockPx(30),
            paddingRight: mockPx(100),
            borderRadius: mockPx(43),
            backgroundColor: '#FFFFFF',
          }}
        >
          <Ionicons name="search-outline" size={mockPx(30)} color={HERO_SEARCH_INK} />
          <TextInput
            ref={inputRef}
            value={query}
            onChangeText={setQuery}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            onSubmitEditing={() => submit(query)}
            placeholder={placeholder}
            placeholderTextColor={HERO_SEARCH_PLACEHOLDER}
            selectionColor={theme.colors.accent}
            returnKeyType="search"
            autoCapitalize="none"
            autoCorrect={false}
            accessibilityLabel="Search properties, localities or projects"
            style={[
              inputStyle,
              {
                flex: 1,
                paddingVertical: 0,
                fontSize: mockPx(26),
                lineHeight: mockPx(32),
                color: HERO_SEARCH_INK,
              },
            ]}
          />
          {query.length > 0 ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Clear search"
              hitSlop={gesture.hitSlop}
              onPress={() => {
                setQuery('');
                inputRef.current?.focus();
              }}
            >
              <Ionicons name="close-circle" size={mockPx(32)} color="#9CA3AF" />
            </Pressable>
          ) : null}
        </View>

        {/* The submit button — the ONE control that runs the full search. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Search"
          onPress={() => submit(query)}
          activeScale={0.94}
          style={{
            position: 'absolute',
            right: mockPx(1),
            top: mockPx(1),
            width: mockPx(84),
            height: mockPx(84),
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: mockPx(42),
            backgroundColor: HERO_SEARCH_BLUE,
          }}
        >
          <Ionicons name="search" size={mockPx(40)} color="#FFFFFF" />
        </PressableScale>
      </View>

      {showPanel ? (
        typing ? (
          preview.isLoading ? (
            <View style={{ marginTop: spacing.sm, gap: spacing.sm }}>
              {[0, 1].map((index) => (
                <Skeleton key={index} height={96} radius={radius.lg} />
              ))}
            </View>
          ) : previewItems.length === 0 ? (
            <Panel>
              <View style={{ paddingHorizontal: spacing.base, paddingVertical: spacing.lg }}>
                <Text variant="callout" tone="muted">
                  No properties match “{preview.term || trimmed}” yet. Try a city or
                  locality, or fewer words.
                </Text>
              </View>
            </Panel>
          ) : (
            <View style={{ marginTop: spacing.sm, gap: spacing.sm }}>
              {previewItems.map((property) => (
                <PropertyListItem key={property.id} property={property} onPress={openProperty} />
              ))}

              {/* Hands the whole query to the Search tab, which owns pagination,
                  filters and sort — the results here are only the first few. */}
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel={
                  more > 0 ? `See all ${preview.total} results` : 'Open in full search'
                }
                onPress={() => submit(query)}
                activeScale={0.98}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: spacing.xs,
                  height: 44,
                  borderRadius: radius.lg,
                  backgroundColor: theme.colors.surface,
                }}
              >
                <Text variant="callout" tone="accent" style={{ fontWeight: '600' }}>
                  {more > 0 ? `See all ${preview.total} results` : 'Open in full search'}
                </Text>
                <Ionicons name="chevron-forward" size={16} color={theme.colors.accent} />
              </PressableScale>
            </View>
          )
        ) : (
          <Panel>
            <RecentSearches
              items={recent.items}
              onSelect={submit}
              onRemove={recent.remove}
              onClear={recent.clear}
            />
          </Panel>
        )
      ) : null}
    </View>
  );
}

/** A surface card for the non-result panel states (recent, empty). Results use
 *  their own cards, so they are not wrapped in this. */
function Panel({ children }: { children: ReactNode }) {
  const theme = useTheme();

  return (
    <View
      style={{
        marginTop: spacing.sm,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
      }}
    >
      {children}
    </View>
  );
}
