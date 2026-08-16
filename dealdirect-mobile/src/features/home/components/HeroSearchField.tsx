import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useRef, useState } from 'react';
import { Pressable, TextInput, View } from 'react-native';

import { useRecentSearches, useSuggestions } from '@/features/search';
import { radius, spacing, useTheme } from '@/theme';
import type { PropertySuggestion } from '@/types/backend/property';
import { Text, useTextInputStyle } from '@/ui';

/**
 * The Home search field. A REAL input, not a button that looks like one.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS REPLACED A FAKE FIELD
 *
 * Home used to render a `PressableScale` styled as a field, which opened a
 * full-screen modal (`SearchSheet`) holding the actual input. Two problems,
 * both reported from real use:
 *
 *   1. It read as a redirect. Tapping a search bar and having the screen
 *      replaced wholesale is indistinguishable from being navigated away, so
 *      "the search bar doesn't work, it just sends me to the search page" was
 *      an accurate description of the experience.
 *   2. It duplicated the Search tab. Two search implementations drift; the
 *      sheet had already drifted, carrying `filters` state with no filter UI
 *      to set it.
 *
 * The website's hero is the model: a real input with a suggestion dropdown
 * that submits onto the results page. This is that, natively.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOES NOT DO
 *
 * It never queries `/properties/search`. Typing costs at most one debounced
 * call to `/properties/suggestions`; committing navigates to the Search tab,
 * which owns results, pagination, filters and compare. One browsing
 * implementation, per HANDOFF §5.3.
 *
 * The suggestion panel is absolutely positioned so the hero below it does not
 * reflow as suggestions arrive and disappear. It is rendered by the parent
 * (which owns the stacking context), not here — see `panel`.
 */

const MIN_QUERY_LENGTH = 2;

export interface HeroSearchFieldProps {
  /** Fires with the committed term. Empty string means "browse everything". */
  onSubmit: (term: string) => void;
  onOpenFilters: () => void;
}

export function HeroSearchField({ onSubmit, onOpenFilters }: HeroSearchFieldProps) {
  const theme = useTheme();
  const inputStyle = useTextInputStyle();
  const inputRef = useRef<TextInput>(null);

  const [value, setValue] = useState('');
  const [focused, setFocused] = useState(false);

  const recent = useRecentSearches();
  // Suggestions are only requested while the panel is actually open. A blurred
  // field with leftover text must not keep spending the shared 20-per-minute
  // search budget.
  const suggestions = useSuggestions(focused ? value : '');

  const commit = useCallback(
    (term: string) => {
      const trimmed = term.trim();
      if (trimmed.length >= MIN_QUERY_LENGTH) recent.add(trimmed);
      inputRef.current?.blur();
      setFocused(false);
      onSubmit(trimmed);
    },
    [onSubmit, recent]
  );

  const showPanel = focused;
  const showSuggestions = value.trim().length >= MIN_QUERY_LENGTH;

  return (
    <View>
      <View
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          height: 44,
          paddingHorizontal: spacing.sm,
        }}
      >
        <Ionicons name="search" size={21} color={theme.colors.textPrimary} />

        <TextInput
          ref={inputRef}
          value={value}
          onChangeText={setValue}
          onFocus={() => setFocused(true)}
          // A tap on a suggestion blurs the field first, so dismissing the
          // panel on blur would unmount the row mid-tap. The panel is closed
          // by `commit` and by the explicit dismiss control instead.
          onSubmitEditing={() => commit(value)}
          placeholder="Search by location, property or keyword…"
          placeholderTextColor={theme.colors.textMuted}
          selectionColor={theme.colors.accent}
          returnKeyType="search"
          autoCapitalize="none"
          autoCorrect={false}
          accessibilityLabel="Search properties"
          /*
            Was a hand-set `fontSize: 16`, which was the same size `body`
            declares but arrived at separately — one of four different
            definitions of what an input's text looks like. It also meant this
            field rendered in the system face while the headline directly above
            it rendered in DM Sans.
          */
          style={[inputStyle, { flex: 1, marginLeft: spacing.md, padding: 0 }]}
        />

        {value.length > 0 ? (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Clear search"
            hitSlop={12}
            onPress={() => {
              setValue('');
              inputRef.current?.focus();
            }}
          >
            <Ionicons name="close-circle" size={19} color={theme.colors.textMuted} />
          </Pressable>
        ) : null}

        <View
          style={{
            width: 1,
            height: 24,
            backgroundColor: theme.colors.border,
            marginHorizontal: spacing.md,
          }}
        />

        {/* This used to be decoration inside the fake field's pressable, so it
            looked like a filter control and did nothing. It opens the real
            filter sheet now. */}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Filters"
          hitSlop={12}
          onPress={onOpenFilters}
        >
          <Ionicons name="options-outline" size={21} color={theme.colors.textPrimary} />
        </Pressable>
      </View>

      {showPanel ? (
        <View
          style={{
            position: 'absolute',
            top: 48,
            left: -spacing.sm,
            right: -spacing.sm,
            zIndex: 20,
            elevation: 20,
            borderRadius: radius.lg,
            backgroundColor: theme.colors.surface,
            borderWidth: 1,
            borderColor: theme.colors.border,
            overflow: 'hidden',
            shadowColor: '#000',
            shadowOpacity: 0.1,
            shadowRadius: 16,
            shadowOffset: { width: 0, height: 8 },
          }}
        >
          {showSuggestions ? (
            <SuggestionRows
              suggestions={suggestions.items}
              isLoading={suggestions.isLoading}
              onSelect={(suggestion) => commit(suggestion.value)}
            />
          ) : recent.items.length > 0 ? (
            <RecentRows items={recent.items} onSelect={commit} />
          ) : (
            <View style={{ padding: spacing.base }}>
              <Text variant="footnote" tone="muted">
                Type a city, locality or project name.
              </Text>
            </View>
          )}
        </View>
      ) : null}
    </View>
  );
}

function SuggestionRows({
  suggestions,
  isLoading,
  onSelect,
}: {
  suggestions: PropertySuggestion[];
  isLoading: boolean;
  onSelect: (suggestion: PropertySuggestion) => void;
}) {
  if (isLoading && suggestions.length === 0) {
    return (
      <View style={{ padding: spacing.base }}>
        <Text variant="footnote" tone="muted">
          Searching…
        </Text>
      </View>
    );
  }

  if (suggestions.length === 0) {
    return (
      <View style={{ padding: spacing.base }}>
        <Text variant="footnote" tone="muted">
          No matches. Press search to look anyway.
        </Text>
      </View>
    );
  }

  return (
    <View>
      {suggestions.map((suggestion) => (
        <Row
          key={`${suggestion.type}:${suggestion.value}`}
          icon={suggestion.type === 'city' || suggestion.type === 'locality' ? 'location-outline' : 'home-outline'}
          label={suggestion.value}
          subtitle={suggestion.subtitle}
          onPress={() => onSelect(suggestion)}
        />
      ))}
    </View>
  );
}

function RecentRows({ items, onSelect }: { items: string[]; onSelect: (term: string) => void }) {
  return (
    <View>
      {items.slice(0, 5).map((term) => (
        <Row key={term} icon="time-outline" label={term} onPress={() => onSelect(term)} />
      ))}
    </View>
  );
}

function Row({
  icon,
  label,
  subtitle,
  onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  subtitle?: string;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={subtitle ? `${label}, ${subtitle}` : label}
      onPress={onPress}
      // Object, not a function — see `ui/Chip.tsx`. As a function this row had
      // no layout at all: NativeWind's interop discards it.
      className="active:opacity-60"
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: spacing.base,
        paddingVertical: spacing.md,
      }}
    >
      <Ionicons name={icon} size={17} color={theme.colors.textMuted} />
      <Text variant="body" numberOfLines={1} className="ml-md flex-1">
        {label}
      </Text>
      {subtitle ? (
        <Text variant="caption" tone="muted" numberOfLines={1} className="ml-sm">
          {subtitle}
        </Text>
      ) : null}
    </Pressable>
  );
}
