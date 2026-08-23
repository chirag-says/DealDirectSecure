import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * Three counts, each a door into Activity.
 *
 * ---------------------------------------------------------------------------
 * EVERY NUMBER HERE IS REAL, OR THE TILE IS NOT DRAWN
 *
 * The temptation on a dashboard is to fill it: "12 new matches", "3 price
 * drops", "your listing was viewed 40 times this week". DealDirect's backend
 * supports none of those — there is no match counter, no price history and no
 * per-period view series — so inventing them would mean a Home screen that
 * lies confidently. The three counts below are the three the app can actually
 * derive:
 *
 *   Shortlist   `features/shortlist`, read from disk. Costs nothing and works
 *               signed out, which is why it is first.
 *   Enquiries   `useSavedProperties`, the same query Activity and every browse
 *               card already run. TanStack dedupes it, so this adds no request
 *               beyond the one the session was going to make anyway.
 *   Searches    `useSavedSearches`, likewise shared with Activity.
 *
 * A tile whose value is still loading renders a dash rather than a zero. Zero
 * is a fact — "you have shortlisted nothing" — and showing it before it is
 * known would tell a returning user their list is empty for as long as the
 * request takes.
 */

export interface SnapshotTile {
  id: string;
  label: string;
  /** Null while unknown. Rendered as an em dash, never as 0. */
  value: number | null;
  icon: keyof typeof Ionicons.glyphMap;
  onPress: () => void;
}

export interface ActivitySnapshotProps {
  tiles: readonly SnapshotTile[];
}

export function ActivitySnapshot({ tiles }: ActivitySnapshotProps) {
  if (tiles.length === 0) return null;

  return (
    <View className="flex-row" style={{ gap: spacing.sm }}>
      {tiles.map((tile) => (
        <Tile key={tile.id} tile={tile} />
      ))}
    </View>
  );
}

function Tile({ tile }: { tile: SnapshotTile }) {
  const theme = useTheme();

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={
        tile.value === null
          ? `${tile.label}, loading`
          : `${tile.value} ${tile.label.toLowerCase()}`
      }
      onPress={tile.onPress}
      activeScale={0.97}
      style={{
        flex: 1,
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: theme.colors.border,
        backgroundColor: theme.colors.surface,
        paddingVertical: spacing.md,
        paddingHorizontal: spacing.sm,
      }}
    >
      <Ionicons name={tile.icon} size={16} color={theme.colors.textMuted} />
      <Text variant="title3" className="mt-xs">
        {tile.value === null ? '—' : tile.value}
      </Text>
      <Text variant="caption" tone="secondary" numberOfLines={1}>
        {tile.label}
      </Text>
    </PressableScale>
  );
}
