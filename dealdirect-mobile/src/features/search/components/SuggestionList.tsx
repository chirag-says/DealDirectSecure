import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, ScrollView, View } from 'react-native';

import { gesture, useTheme } from '@/theme';
import { Skeleton, Text } from '@/ui';
import type { PropertySuggestion } from '@/types/backend/property';

/**
 * Autocomplete panel, and the recent-searches panel that stands in for it
 * before the user has typed enough to query.
 *
 * The three suggestion kinds get distinct icons because they mean different
 * things: `project` is a listing title, `locality` is an area, `city` is a city.
 * A user picking blind between three identical-looking rows learns nothing from
 * the result.
 */

const ICON_FOR_TYPE = {
  project: 'business-outline',
  locality: 'navigate-outline',
  city: 'location-outline',
} as const;

export interface SuggestionListProps {
  suggestions: PropertySuggestion[];
  isLoading: boolean;
  /** The term the panel is currently reflecting, for the empty message. */
  term: string;
  onSelect: (suggestion: PropertySuggestion) => void;
}

export function SuggestionList({ suggestions, isLoading, term, onSelect }: SuggestionListProps) {
  const theme = useTheme();

  if (isLoading) {
    return (
      <View className="gap-md px-base py-base">
        {[0, 1, 2].map((index) => (
          <Skeleton key={index} height={20} />
        ))}
      </View>
    );
  }

  if (suggestions.length === 0) {
    return (
      <View className="px-base py-lg">
        <Text variant="callout" tone="muted">
          No matches for “{term}”. Press search to look through titles and
          descriptions too.
        </Text>
      </View>
    );
  }

  return (
    <ScrollView keyboardShouldPersistTaps="handled">
      {suggestions.map((suggestion) => (
        <Pressable
          key={`${suggestion.type}:${suggestion.value}`}
          accessibilityRole="button"
          accessibilityLabel={`${suggestion.value}${suggestion.subtitle ? `, ${suggestion.subtitle}` : ''}`}
          onPress={() => onSelect(suggestion)}
          className="flex-row items-center border-b border-border px-base py-md active:opacity-70"
        >
          <Ionicons
            name={ICON_FOR_TYPE[suggestion.type]}
            size={18}
            color={theme.colors.textMuted}
          />
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
      ))}
    </ScrollView>
  );
}

export interface RecentSearchesProps {
  items: string[];
  onSelect: (term: string) => void;
  onRemove: (term: string) => void;
  onClear: () => void;
}

export function RecentSearches({ items, onSelect, onRemove, onClear }: RecentSearchesProps) {
  const theme = useTheme();

  if (items.length === 0) return null;

  return (
    <View className="pt-base">
      <View className="flex-row items-center justify-between px-base pb-sm">
        <Text variant="subhead" tone="secondary">
          Recent
        </Text>
        <Pressable accessibilityRole="button" hitSlop={gesture.hitSlop} onPress={onClear}>
          <Text variant="footnote" tone="accent">
            Clear
          </Text>
        </Pressable>
      </View>

      {items.map((term) => (
        <View key={term} className="flex-row items-center border-b border-border px-base">
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Search ${term}`}
            onPress={() => onSelect(term)}
            className="flex-1 flex-row items-center py-md active:opacity-70"
          >
            <Ionicons name="time-outline" size={18} color={theme.colors.textMuted} />
            <Text variant="body" numberOfLines={1} className="ml-md flex-1">
              {term}
            </Text>
          </Pressable>

          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Remove ${term} from recent searches`}
            hitSlop={gesture.hitSlop}
            onPress={() => onRemove(term)}
            className="pl-md"
          >
            <Ionicons name="close" size={16} color={theme.colors.textMuted} />
          </Pressable>
        </View>
      ))}
    </View>
  );
}
