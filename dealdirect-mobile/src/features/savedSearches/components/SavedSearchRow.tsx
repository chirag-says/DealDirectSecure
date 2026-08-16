import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { Pressable, Switch, View } from 'react-native';

import { useTheme } from '@/theme';
import { Text } from '@/ui';
import type { SavedSearchSummary } from '../types';

/**
 * One saved search.
 *
 * The switch controls IN-APP ALERTS, not the search's existence. It writes
 * `notifyInApp` through `PUT /saved-searches/:id`, which is reversible. The
 * backend's `isActive` toggle is deliberately not wired to anything: turning
 * it off removes the search from the only endpoint that lists it, so the user
 * could never turn it back on. See `hooks.ts`.
 *
 * A search that cannot alert says so. The backend accepts a search whose only
 * filter is free text, and its matcher never reads that field, so such a
 * search is silent forever. Rather than let the user wait for alerts that
 * cannot arrive, the row is marked and the switch is disabled — an alert
 * toggle on something that cannot alert is a lie in miniature.
 */

export interface SavedSearchRowProps {
  search: SavedSearchSummary;
  onPress: (search: SavedSearchSummary) => void;
  onToggleAlerts: (id: string, notifyInApp: boolean) => void;
  onDelete: (search: SavedSearchSummary) => void;
}

function SavedSearchRowComponent({
  search,
  onPress,
  onToggleAlerts,
  onDelete,
}: SavedSearchRowProps) {
  const theme = useTheme();

  const handlePress = useCallback(() => onPress(search), [onPress, search]);
  const handleToggle = useCallback(
    (next: boolean) => onToggleAlerts(search.id, next),
    [onToggleAlerts, search.id]
  );
  const handleDelete = useCallback(() => onDelete(search), [onDelete, search]);

  return (
    <View className="rounded-xl border border-border bg-surface">
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Run search ${search.name}`}
        onPress={handlePress}
        className="flex-row items-center px-md pt-md pb-sm active:opacity-70"
      >
        <View className="flex-1">
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {search.name}
          </Text>
          {search.description ? (
            <Text variant="footnote" tone="muted" numberOfLines={2} className="mt-xs">
              {search.description}
            </Text>
          ) : null}
        </View>

        <Ionicons name="chevron-forward" size={18} color={theme.colors.textMuted} />
      </Pressable>

      {search.isInert ? (
        <View className="flex-row items-start px-md pb-sm">
          <Ionicons name="alert-circle-outline" size={15} color={theme.colors.warning} />
          <Text variant="caption" tone="muted" className="ml-xs flex-1">
            This search has no filter that alerts can match, so it will not notify you. Tap it to
            run the search, or save a new one with a city or price range.
          </Text>
        </View>
      ) : null}

      <View className="flex-row items-center border-t border-border px-md py-sm">
        <Text variant="footnote" tone="secondary" className="flex-1">
          Alert me in the app
        </Text>

        <Switch
          value={search.notifyInApp && !search.isInert}
          onValueChange={handleToggle}
          disabled={search.isInert}
          accessibilityLabel={`In-app alerts for ${search.name}`}
        />

        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`Delete search ${search.name}`}
          onPress={handleDelete}
          hitSlop={10}
          className="ml-md active:opacity-60"
        >
          <Ionicons name="trash-outline" size={19} color={theme.colors.textMuted} />
        </Pressable>
      </View>
    </View>
  );
}

export const SavedSearchRow = memo(SavedSearchRowComponent);
