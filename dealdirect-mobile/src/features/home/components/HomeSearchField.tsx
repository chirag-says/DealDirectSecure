import Ionicons from '@expo/vector-icons/Ionicons';
import { useRef, useState } from 'react';
import { Pressable, TextInput, View } from 'react-native';

import { RecentSearches, useRecentSearches, useSuggestions } from '@/features/search';
import { gesture, radius, spacing, useTheme } from '@/theme';
import type { PropertySuggestion } from '@/types/backend/property';
import { PressableScale, Skeleton, Text, useTextInputStyle } from '@/ui';
import type { City } from '../cities';

/**
 * The hero's search field — a real input that answers in place.
 *
 * ---------------------------------------------------------------------------
 * WHY IT NO LONGER JUST JUMPS TO THE SEARCH TAB
 *
 * This used to be a button dressed as a search box: tapping it anywhere
 * navigated straight to the Search screen, so the field on Home was a decoy
 * for the real one a tab away. A person who taps a search box expects to type
 * into it, and the first thing they got instead was a screen change.
 *
 * Now they type here. Autocomplete shows under the field as they go — the SAME
 * suggestions the Search tab uses, so there is one source and one rate budget,
 * not a second implementation. The screen only CHANGES on a deliberate search:
 * the submit button, the keyboard's search key, or picking a suggestion.
 * Focusing the field, and typing into it, keep the user on Home.
 *
 * ---------------------------------------------------------------------------
 * THE PANEL IS RENDERED INLINE, NOT AS A FLOATING DROPDOWN
 *
 * It sits in the hero's own column and grows the block downward while focused,
 * rather than floating over the content below on an absolute layer. A floating
 * panel inside a scroll view has to fight the scroll for its anchor; an inline
 * one cannot drift, and the keyboard covers the pushed-down content anyway.
 * Capped at a handful of rows so it never needs a scroll view of its own nested
 * inside Home's — the one gesture conflict worth designing out entirely.
 *
 * ---------------------------------------------------------------------------
 * THE SAME RATE DISCIPLINE AS THE SEARCH TAB
 *
 * `useSuggestions` is fed the query only while the field is focused, and it
 * debounces at 450ms with a two-character floor before it will touch the
 * shared 20-per-minute search limiter. Recent searches are a synchronous MMKV
 * read, so the focused-but-empty state costs nothing.
 */

const ICON_FOR_TYPE = {
  project: 'business-outline',
  locality: 'navigate-outline',
  city: 'location-outline',
} as const;

/** How many suggestion rows the inline panel shows before it would need to
 *  scroll. Kept low deliberately: see the panel note in the module doc. */
const MAX_INLINE_SUGGESTIONS = 6;

export interface HomeSearchFieldProps {
  /** The scoped city, for the placeholder. The redirect adds the filter. */
  city: City | null;
  /**
   * Run a search. Empty term means "browse everything". The caller owns the
   * navigation and rides the selected city along; this component only decides
   * WHEN a search is deliberate enough to leave Home for.
   */
  onSubmit: (term: string) => void;
}

export function HomeSearchField({ city, onSubmit }: HomeSearchFieldProps) {
  const theme = useTheme();
  const inputStyle = useTextInputStyle();
  const inputRef = useRef<TextInput>(null);

  const [query, setQuery] = useState('');
  const [focused, setFocused] = useState(false);

  const recent = useRecentSearches();
  // Only queried while focused, so a blurred field with stale text fires
  // nothing. The hook's own debounce and two-char floor guard the limiter.
  const suggestions = useSuggestions(focused ? query : '');

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

  const placeholder = city ? `Search in ${city.label}` : 'Search locality, project or city';

  return (
    <View style={{ marginTop: spacing.base }}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: spacing.sm }}>
        {/* The field. A real input now, styled as the pill the trigger used to
            imitate, so nothing about the hero's shape changed. */}
        <View
          style={{
            flex: 1,
            flexDirection: 'row',
            alignItems: 'center',
            gap: spacing.sm,
            height: 52,
            paddingHorizontal: spacing.base,
            borderRadius: radius.full,
            backgroundColor: theme.colors.surface,
          }}
        >
          <Ionicons name="search" size={20} color={theme.colors.textSecondary} />
          <TextInput
            ref={inputRef}
            value={query}
            onChangeText={setQuery}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            onSubmitEditing={() => submit(query)}
            placeholder={placeholder}
            placeholderTextColor={theme.colors.textSecondary}
            selectionColor={theme.colors.accent}
            returnKeyType="search"
            autoCapitalize="none"
            autoCorrect={false}
            accessibilityLabel="Search properties, localities or projects"
            style={[inputStyle, { flex: 1, paddingVertical: spacing.md }]}
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
              <Ionicons name="close-circle" size={18} color={theme.colors.textMuted} />
            </Pressable>
          ) : null}
        </View>

        {/* The search button — the ONE control that leaves Home. Surface fill,
            not brand: a brand-red button on the brand-red hero would vanish. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Search"
          onPress={() => submit(query)}
          activeScale={0.94}
          style={{
            width: 52,
            height: 52,
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: radius.full,
            backgroundColor: theme.colors.surface,
          }}
        >
          <Ionicons name="arrow-forward" size={20} color={theme.colors.brand} />
        </PressableScale>
      </View>

      {showPanel ? (
        <View
          style={{
            marginTop: spacing.sm,
            borderRadius: radius.lg,
            backgroundColor: theme.colors.surface,
            overflow: 'hidden',
          }}
        >
          {typing ? (
            suggestions.isLoading ? (
              <View style={{ padding: spacing.base, gap: spacing.md }}>
                {[0, 1, 2].map((index) => (
                  <Skeleton key={index} height={18} />
                ))}
              </View>
            ) : suggestions.items.length === 0 ? (
              <View style={{ paddingHorizontal: spacing.base, paddingVertical: spacing.lg }}>
                <Text variant="callout" tone="muted">
                  No matches for “{suggestions.term || trimmed}”. Press search to look
                  through titles and descriptions too.
                </Text>
              </View>
            ) : (
              suggestions.items
                .slice(0, MAX_INLINE_SUGGESTIONS)
                .map((suggestion) => (
                  <SuggestionRow
                    key={`${suggestion.type}:${suggestion.value}`}
                    suggestion={suggestion}
                    onPress={() => submit(suggestion.value)}
                  />
                ))
            )
          ) : (
            <RecentSearches
              items={recent.items}
              onSelect={submit}
              onRemove={recent.remove}
              onClear={recent.clear}
            />
          )}
        </View>
      ) : null}
    </View>
  );
}

function SuggestionRow({
  suggestion,
  onPress,
}: {
  suggestion: PropertySuggestion;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${suggestion.value}${suggestion.subtitle ? `, ${suggestion.subtitle}` : ''}`}
      onPress={onPress}
      className="flex-row items-center border-b border-border px-base py-md active:opacity-70"
    >
      <Ionicons name={ICON_FOR_TYPE[suggestion.type]} size={18} color={theme.colors.textMuted} />
      <View className="ml-md flex-1">
        <Text variant="body" numberOfLines={1}>
          {suggestion.value}
        </Text>
        {suggestion.subtitle ? (
          <Text variant="caption" tone="muted" numberOfLines={1}>
            {suggestion.subtitle}
          </Text>
        ) : null}
      </View>
    </Pressable>
  );
}
