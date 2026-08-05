import { Image as RNImage, View, useWindowDimensions } from 'react-native';

import { radius, spacing } from '@/theme';
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
 * request rather than written down, and `cities.ts` for why the same city under
 * two spellings still produces one tile.
 *
 * Cities with no inventory are absent, not greyed out. A tile that leads to an
 * empty list teaches the user that the app has nothing, when the truth is that
 * this one shortcut has nothing.
 */

/** Four across, matching the ported original. */
const COLUMNS = 4;

export interface CityGridProps {
  onSelect: (term: string) => void;
}

export function CityGrid({ onSelect }: CityGridProps) {
  const { width } = useWindowDimensions();
  const { cities, isLoading, atCeiling } = useCityCounts();

  // Screen gutters plus the gaps between columns, divided out. Computed rather
  // than a magic number so the tile still fits when the gutter changes.
  const gap = spacing.md;
  const tileWidth = Math.floor(
    (width - spacing.base * 2 - gap * (COLUMNS - 1)) / COLUMNS
  );

  if (isLoading) {
    return (
      <View
        className="flex-row flex-wrap px-base"
        style={{ gap }}
        accessibilityLabel="Loading cities"
      >
        {Array.from({ length: 8 }, (_, index) => (
          <View key={index} style={{ width: tileWidth }}>
            <Skeleton width={tileWidth} height={tileWidth} radius={radius.lg} />
            <Skeleton width={tileWidth * 0.7} height={11} radius={4} className="mt-sm" />
          </View>
        ))}
      </View>
    );
  }

  if (cities.length === 0) return null;

  return (
    <View className="flex-row flex-wrap px-base" style={{ gap }}>
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
  /*
   * "9" when the count is exact, "9+" when the corpus outgrew one page and this
   * is a lower bound. The suffix is the difference between a number that is
   * imprecise and a number that is wrong, and it costs one character.
   */
  const label = `${count}${approximate ? '+' : ''}`;

  return (
    <PressableScale
      accessibilityLabel={`${city.label}, ${count}${approximate ? ' or more' : ''} propert${count === 1 ? 'y' : 'ies'}`}
      onPress={onPress}
      style={{ width }}
    >
      <RNImage
        source={city.image}
        style={{ width, height: width, borderRadius: radius.lg }}
        resizeMode="cover"
      />

      <Text variant="caption" className="mt-sm text-center" numberOfLines={1}>
        {city.label}
      </Text>
      <Text variant="caption" tone="muted" className="text-center">
        {label}
      </Text>
    </PressableScale>
  );
}
