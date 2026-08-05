import Ionicons from '@expo/vector-icons/Ionicons';
import { forwardRef } from 'react';
import { Pressable, TextInput, View } from 'react-native';

import { gesture, useTheme } from '@/theme';
import { Text } from '@/ui';

/**
 * Search field.
 *
 * Not the `Input` primitive: that one reserves space for a label and a
 * validation line, and a search field has neither. It is a single-line control
 * with a clear affordance and a submit key, so it is built as one.
 *
 * `returnKeyType="search"` matters more than it looks. Autocomplete is
 * debounced, so a user who types fast and stops arrives at a screen that has
 * not fetched yet; the keyboard's search key is the escape hatch that runs the
 * query immediately.
 */

export interface SearchBarProps {
  value: string;
  onChangeText: (value: string) => void;
  onSubmit: () => void;
  onClear: () => void;
  /** Fires on focus so the screen can switch back into editing mode. */
  onFocus?: () => void;
  placeholder?: string;
  autoFocus?: boolean;
}

export const SearchBar = forwardRef<TextInput, SearchBarProps>(function SearchBar(
  {
    value,
    onChangeText,
    onSubmit,
    onClear,
    onFocus,
    placeholder = 'Search city, locality or project',
    autoFocus = false,
  },
  ref
) {
  const theme = useTheme();

  return (
    <View className="flex-row items-center rounded-full border border-border bg-surface-muted px-md">
      <Ionicons name="search" size={18} color={theme.colors.textMuted} />

      <TextInput
        ref={ref}
        value={value}
        onChangeText={onChangeText}
        onSubmitEditing={onSubmit}
        onFocus={onFocus}
        placeholder={placeholder}
        placeholderTextColor={theme.colors.textMuted}
        selectionColor={theme.colors.accent}
        returnKeyType="search"
        autoCapitalize="none"
        autoCorrect={false}
        autoFocus={autoFocus}
        accessibilityLabel="Search properties"
        className="flex-1 py-md pl-sm text-body text-text-primary"
      />

      {value.length > 0 ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Clear search"
          hitSlop={gesture.hitSlop}
          onPress={onClear}
        >
          <Ionicons name="close-circle" size={18} color={theme.colors.textMuted} />
        </Pressable>
      ) : null}
    </View>
  );
});

/**
 * A search field that is not a field.
 *
 * The Explore tab shows this and routes to the Search tab on tap. Rendering a
 * real, focusable input on a screen whose job is browsing invites the keyboard
 * to cover the feed for no reason.
 */
export function SearchTrigger({ onPress, label }: { onPress: () => void; label?: string }) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="search"
      accessibilityLabel={label ?? 'Search properties'}
      onPress={onPress}
      // Border only, no fill. A grey pill on a white feed reads as a disabled
      // field; a hairline outline reads as an affordance waiting to be used.
      className="flex-row items-center rounded-full border border-border-strong px-base py-md"
      style={({ pressed }) => (pressed ? { opacity: 0.85 } : undefined)}
    >
      <Ionicons name="search" size={18} color={theme.colors.textSecondary} />
      <Text variant="body" tone={label ? 'primary' : 'secondary'} numberOfLines={1} className="ml-sm flex-1">
        {label ?? 'Search city, locality or project'}
      </Text>
    </Pressable>
  );
}
