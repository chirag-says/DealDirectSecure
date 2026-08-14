import Ionicons from '@expo/vector-icons/Ionicons';
import { View, useWindowDimensions } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { PressableScale, Skeleton, Text } from '@/ui';
import { citySearchTerm, type City } from '../cities';
import { useCityCounts } from '../useCityCounts';

/**
 * Explore by city.
 *
 * A grid rather than a rail, and it is the one section on Home that should be:
 * cities are a small closed set the user is scanning for THEIR city, not
 * browsing for inspiration. A rail hides two thirds of a closed set behind a
 * gesture, which turns a lookup into a search. Everything editorial on this
 * screen scrolls sideways; this does not, for that reason.
 *
 * Counts are live. See `useCityCounts` for why they are computed from one
 * request rather than written down, and `cities.ts` for why the same city
 * under two spellings still produces one tile.
 *
 * Cities with no inventory are absent, not greyed out. A tile that leads to an
 * empty list teaches the user that the app has nothing, when the truth is that
 * this one shortcut has nothing.
 *
 * ---------------------------------------------------------------------------
 * TYPOGRAPHIC TILES, NOT THE ILLUSTRATED LANDMARK ICONS `cities.ts` STILL CARRIES
 *
 * Each `City` in `cities.ts` still points at a line-art landmark PNG (Gateway
 * of India for Mumbai, and so on), ported from the original app. The brief for
 * this redesign is explicit that this exact treatment — illustrated city icons
 * — is what to avoid: it is the one piece of clip-art on an otherwise
 * photography-and-typography screen, and it reads as a template rather than as
 * DealDirect's own. So this grid stops reading `city.image` entirely and
 * builds the tile from type alone: the name, the live count, and an arrow.
 * The artwork stays in the repo — `cities.ts` still exports it — in case a
 * future screen wants it; nothing here still requires it.
 */

/** Two across. A typographic tile needs more width per column than an icon did. */
const COLUMNS = 2;

export interface CityGridProps {
  onSelect: (term: string) => void;
}

export function CityGrid({ onSelect }: CityGridProps) {
  const { width } = useWindowDimensions();
  const { cities, isLoading, atCeiling } = useCityCounts();

  const gap = spacing.md;
  const tileWidth = Math.floor((width - spacing.lg * 2 - gap * (COLUMNS - 1)) / COLUMNS);

  if (isLoading) {
    return (
      <View className="flex-row flex-wrap px-lg" style={{ gap }} accessibilityLabel="Loading cities">
        {Array.from({ length: 6 }, (_, index) => (
          <Skeleton key={index} width={tileWidth} height={72} radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (cities.length === 0) return null;

  return (
    <View className="flex-row flex-wrap px-lg" style={{ gap }}>
      {cities.map(({ city, count }) => (
        <CityTile
          key={city.id}
          city={city}
          count={count}
          approximate={atCeiling}
          width={tileWidth}
          onPress={() => onSelect(citySearchTerm(city))}
        />
      ))}
    </View>
  );
}

function CityTile({
  city,
  count,
  approximate,
  width,
  onPress,
}: {
  city: City;
  count: number;
  approximate: boolean;
  width: number;
  onPress: () => void;
}) {
  const theme = useTheme();
  /*
   * "9" when the count is exact, "9+" when the corpus outgrew one page and this
   * is a lower bound. The suffix is the difference between a number that is
   * imprecise and a number that is wrong, and it costs one character.
   */
  const label = `${count}${approximate ? '+' : ''} propert${count === 1 ? 'y' : 'ies'}`;

  return (
    <PressableScale
      accessibilityLabel={`${city.label}, ${count}${approximate ? ' or more' : ''} propert${count === 1 ? 'y' : 'ies'}`}
      onPress={onPress}
      style={{
        width,
        padding: spacing.base,
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: theme.colors.border,
        justifyContent: 'space-between',
      }}
    >
      <View className="flex-row items-start justify-between">
        <Text variant="bodyEmphasis" numberOfLines={1} className="flex-1">
          {city.label}
        </Text>
        <Ionicons name="arrow-forward" size={14} color={theme.colors.brand} />
      </View>

      <Text variant="footnote" tone="muted" className="mt-xs">
        {label}
      </Text>
    </PressableScale>
  );
}
