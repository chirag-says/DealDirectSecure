import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, ScrollView, View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Text } from '@/ui';
import { BROWSE_SHORTCUTS, POPULAR_SEARCHES, type BrowseShortcut } from '../catalog';

/**
 * Browse-by-type tiles and popular-search chips.
 *
 * Both are shortcuts into the same browse screen with a term prefilled, so they
 * are built from one table each in `../catalog.ts` rather than hand-written
 * here. Every term in those tables was probed against live data — a tile that
 * lands on an empty screen reads as "this app has no apartments", not "that
 * shortcut is broken".
 */

export interface BrowseRowProps {
  onSelect: (term: string) => void;
}

export function BrowseRow({ onSelect }: BrowseRowProps) {
  return (
    <ScrollView
      horizontal
      showsHorizontalScrollIndicator={false}
      contentContainerStyle={ROW_STYLE}
    >
      {BROWSE_SHORTCUTS.map((shortcut) => (
        <BrowseTile key={shortcut.id} shortcut={shortcut} onPress={() => onSelect(shortcut.term)} />
      ))}
    </ScrollView>
  );
}

function BrowseTile({ shortcut, onPress }: { shortcut: BrowseShortcut; onPress: () => void }) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`Browse ${shortcut.label}`}
      onPress={onPress}
      className="items-center active:opacity-75"
    >
      <View
        className="items-center justify-center border border-border bg-surface-muted"
        style={{ width: 68, height: 68, borderRadius: radius.lg }}
      >
        <Ionicons name={shortcut.icon as never} size={24} color={theme.colors.textSecondary} />
      </View>
      <Text variant="caption" tone="secondary" className="mt-sm">
        {shortcut.label}
      </Text>
    </Pressable>
  );
}

export function PopularSearches({ onSelect }: BrowseRowProps) {
  return (
    <View className="flex-row flex-wrap gap-sm px-base">
      {POPULAR_SEARCHES.map((term) => (
        <Pressable
          key={term}
          accessibilityRole="button"
          accessibilityLabel={`Search ${term}`}
          onPress={() => onSelect(term)}
          className="rounded-full border border-border px-md py-sm active:opacity-75"
        >
          <Text variant="footnote" tone="secondary">
            {term}
          </Text>
        </Pressable>
      ))}
    </View>
  );
}

const ROW_STYLE = { gap: spacing.base, paddingHorizontal: spacing.base } as const;
