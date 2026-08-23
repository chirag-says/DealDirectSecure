import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, radius, spacing, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';
import {
  BHK_OPTIONS,
  CATEGORY_OPTIONS,
  CITY_OPTIONS,
  CONSTRUCTION_STATUS_OPTIONS,
  FURNISHING_OPTIONS,
  PRICE_BANDS,
  type SearchFilters,
} from '../filters';
import type { ResumableSearch } from '../resume';

/**
 * "Continue your search".
 *
 * The first thing on the tab for a returning user, and the only surface in the
 * app that treats a property search as something that spans sessions — which
 * is what it actually is. Somebody who narrowed to 2 BHK rentals in Pune under
 * a price band on Tuesday should not have to rebuild that on Saturday, and a
 * recent-search chip reading "Pune" does not carry it: it restores one word out
 * of five decisions.
 *
 * Renders only when there is something to resume, so it never occupies the
 * fold on a first session.
 *
 * ---------------------------------------------------------------------------
 * THE CRITERIA ARE SPELLED OUT, NOT COUNTED
 *
 * "4 filters" is a number the user has to open something to decode. The chips
 * say what the filters ARE, which is what lets someone decide whether to
 * resume or start fresh without tapping anything.
 *
 * The count is prefixed "about", and that is not hedging. It is the figure
 * recorded when the search last ran; inventory moves, and this card does not
 * re-run the query to check, because a card that costs a request every time
 * the tab opens is exactly the kind of prettiness the idle state cannot
 * afford. See `resume.ts`.
 */

export interface ResumeSearchCardProps {
  search: ResumableSearch;
  onResume: (filters: SearchFilters) => void;
  onDismiss: () => void;
}

export function ResumeSearchCard({ search, onResume, onDismiss }: ResumeSearchCardProps) {
  const theme = useTheme();
  const chips = describeFilters(search.filters);

  return (
    <View
      style={{
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: theme.colors.border,
        backgroundColor: theme.colors.surface,
        padding: spacing.base,
      }}
    >
      <View className="flex-row items-start justify-between">
        <View className="flex-1 flex-row items-center" style={{ gap: spacing.sm }}>
          <Ionicons name="time-outline" size={16} color={theme.colors.textMuted} />
          <Text variant="footnote" tone="secondary">
            Continue your search
          </Text>
        </View>

        {/* Quiet, and deliberately not a confirmation. Dismissing loses a
            device-local convenience, nothing else; a dialog here would teach
            users to dismiss the ones that matter. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Dismiss this search"
          hitSlop={gesture.hitSlop}
          onPress={onDismiss}
        >
          <Ionicons name="close" size={18} color={theme.colors.textMuted} />
        </PressableScale>
      </View>

      <Text variant="bodyEmphasis" numberOfLines={1} className="mt-sm">
        {search.filters.query.trim() || 'All properties'}
      </Text>

      {chips.length > 0 ? (
        <View className="mt-sm flex-row flex-wrap" style={{ gap: spacing.xs }}>
          {chips.map((chip) => (
            <View
              key={chip}
              style={{
                borderRadius: radius.full,
                backgroundColor: theme.colors.surfaceMuted,
                paddingHorizontal: spacing.sm,
                paddingVertical: 2,
              }}
            >
              <Text variant="caption" tone="secondary">
                {chip}
              </Text>
            </View>
          ))}
        </View>
      ) : null}

      <View className="mt-base flex-row items-center justify-between">
        <Text variant="caption" tone="muted">
          {search.resultCount > 0
            ? `about ${search.resultCount} ${search.resultCount === 1 ? 'match' : 'matches'} last time`
            : 'No matches last time'}
        </Text>

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Resume this search"
          onPress={() => onResume(search.filters)}
          style={{
            borderRadius: radius.full,
            backgroundColor: theme.colors.accentMuted,
            paddingHorizontal: spacing.base,
            paddingVertical: spacing.xs,
          }}
        >
          <Text variant="footnote" tone="accent" style={{ fontWeight: '600' }}>
            Resume
          </Text>
        </PressableScale>
      </View>
    </View>
  );
}

/**
 * The filter set as human-readable chips, in the order a person would say it.
 *
 * `query` is excluded — it is the card's title, and repeating it as a chip
 * reads as two different filters.
 */
function describeFilters(filters: SearchFilters): string[] {
  const chips: string[] = [];

  if (filters.listingType) chips.push(filters.listingType === 'rent' ? 'Rent' : 'Buy');

  const label = (
    table: readonly { label: string; value: string }[],
    value: string | undefined
  ): string | undefined => table.find((option) => option.value === value)?.label;

  const band = PRICE_BANDS.find((option) => option.id === filters.priceBand)?.label;
  if (band) chips.push(band);

  const bhk = label(BHK_OPTIONS, filters.bhk);
  if (bhk) chips.push(bhk);

  const city = label(CITY_OPTIONS, filters.city);
  if (city) chips.push(city);

  const category = label(CATEGORY_OPTIONS, filters.categoryName);
  if (category) chips.push(category);

  const furnishing = label(FURNISHING_OPTIONS, filters.furnishing);
  if (furnishing) chips.push(furnishing);

  const construction = label(CONSTRUCTION_STATUS_OPTIONS, filters.constructionStatus);
  if (construction) chips.push(construction);

  return chips;
}
