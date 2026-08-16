import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { View } from 'react-native';

import { relativeDay } from '@/lib';
import { spacing, useTheme } from '@/theme';
import { formatRatePerSqft, PressableScale, PriceLabel, Text } from '@/ui';
import type { PropertySummary } from '../types';
import {
  CARD_RADIUS,
  cardShadow,
  CompareControl,
  Cover,
  COVER_ASPECT,
  CONTROL_INSET,
  IntentBadge,
  OVERLAY_INSET,
  PhotoCount,
  SaveControl,
  SpecRow,
  specs,
  type CompareControlProps,
  type SaveControlProps,
} from './cardParts';

/**
 * The feed card: full-width photo, structured text under it.
 *
 * Answers "do I like this", which is why the photograph gets the width. The
 * compact row (`PropertyListItem`) answers "how do these ten compare", which is
 * why it gives the same area to text instead. Neither is a shrunken version of
 * the other and the toggle between them is not a style preference.
 *
 * ---------------------------------------------------------------------------
 * ONE COMPONENT, NOT A PHOTO WITH UI ATTACHED
 *
 * The structure is fixed and every part of it is stated here rather than being
 * an accident of what was added last:
 *
 *   photo          3:2, flush to the card edges, clipped by the card radius
 *     overlays     intent top-left, save top-right, photo count bottom-right
 *   content        16pt on all four sides
 *     price row    price, and its per-sqft rate right-aligned on the same line
 *     location     8 below
 *     specs        12 below
 *     provenance   12 below, separated because it is context, not an attribute
 *
 * Three gap sizes, from the spacing scale, chosen by how related two things
 * are: 4 inside a group, 8 between a line and its subordinate, 12 between
 * groups. The old card used 4 everywhere, which is why it read as one
 * undifferentiated block however good the words were.
 *
 * ---------------------------------------------------------------------------
 * ONE FOCAL POINT
 *
 * Price at `title2`, and nothing else on the card comes near that weight. A
 * feed is scanned by price; every other field is read only after the price has
 * already decided whether to keep reading.
 *
 * Nothing here is invented. The photo count, the unit rate, the posted date and
 * the view count are fields on the row or arithmetic over two of them. The
 * reference cards this was measured against carry a fifth signal we cannot
 * honestly match — 99acres' "Verified", Square Yards' RERA badge — because this
 * backend has no verification state. An unearned trust badge is worse than
 * none.
 *
 * Memoised with a `useCallback` press handler: this renders once per row and an
 * allocation here is multiplied by scroll distance.
 */

/**
 * Below this the view count is suppressed.
 *
 * Ten is where the number starts carrying information. Under it the figure is
 * as likely to be the owner reloading their own listing as it is to be demand,
 * and "2 views" tells a buyer the listing is ignored — which may be true, but
 * is not a claim this card has the standing to make on the strength of a
 * counter that also counts crawlers.
 */
const MEANINGFUL_VIEW_COUNT = 10;

export interface PropertyCardProps {
  property: PropertySummary;
  onPress: (id: string) => void;
  /**
   * The heart. Omitted only where saving makes no sense — the owner's own
   * listings screen. Every browse surface passes it.
   */
  save?: SaveControlProps;
  /**
   * Replaces the save control while compare mode is on. The two never render
   * together: one corner, one action, always.
   */
  compare?: CompareControlProps;
}

function PropertyCardComponent({ property, onPress, save, compare }: PropertyCardProps) {
  const theme = useTheme();
  const facts = specs(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  /*
   * The unit rate, and why only on sales.
   *
   * "₹6,800 / sqft" is what makes two sale listings comparable and it is how
   * every portal prints them. On a RENTAL the same arithmetic gives "₹36 /
   * sqft", a monthly figure that reads as a purchase price unless it carries a
   * "/month" the card has no room for. Commercial leasing does quote rent per
   * sqft per month; residential does not, and this card cannot tell which it is
   * looking at with enough confidence to switch the label.
   */
  const rate =
    property.intent === 'rent' ? null : formatRatePerSqft(property.priceRupees, property.areaSqft);

  const posted = relativeDay(property.createdAt);
  const showViews = property.views >= MEANINGFUL_VIEW_COUNT;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={handlePress}
      activeScale={0.985}
      style={{
        borderRadius: CARD_RADIUS,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        ...cardShadow,
      }}
    >
      <View>
        <Cover uri={property.coverImage} aspectRatio={COVER_ASPECT} />

        {/*
          Three overlays, three assigned corners, one inset — see
          `OVERLAY_INSET`. The control sits closer to the edge than the badge
          because its 44pt target is wider than the 34pt disc inside it, so
          that the two visible objects line up rather than the two boxes.
        */}
        <View className="absolute left-0 top-0" style={{ margin: OVERLAY_INSET }}>
          <IntentBadge intent={property.intent} />
        </View>

        <View className="absolute right-0 top-0" style={{ margin: CONTROL_INSET }}>
          {compare ? (
            <CompareControl {...compare} />
          ) : save ? (
            <SaveControl {...save} />
          ) : null}
        </View>

        <View className="absolute bottom-0 right-0" style={{ margin: OVERLAY_INSET }}>
          <PhotoCount count={property.imageCount} />
        </View>
      </View>

      <View style={{ padding: spacing.base }}>
        {/*
          The rate sits on the SAME line as the price, right-aligned and two
          steps down the scale. It is a footnote to the price, not a second
          price, and its own line would give it a whole row of prominence it
          has not earned.
        */}
        <View className="flex-row items-end justify-between">
          <PriceLabel
            price={property.priceRupees}
            variant="title2"
            suffix={property.intent === 'rent' ? '/month' : undefined}
          />
          {rate ? (
            <Text variant="caption" tone="muted" className="ml-sm pb-xs">
              {rate}
            </Text>
          ) : null}
        </View>

        {property.locationLabel ? (
          <View className="mt-sm flex-row items-center">
            <Ionicons name="location-outline" size={14} color={theme.colors.textMuted} />
            <Text variant="callout" numberOfLines={1} className="ml-xs flex-1">
              {property.locationLabel}
            </Text>
          </View>
        ) : null}

        {facts.length > 0 ? (
          <View className="mt-md">
            <SpecRow items={facts} />
          </View>
        ) : null}

        {/*
          Only reached by listings whose owner wrote a real title — most are
          machine-composed from the fields already shown above, see
          `isGeneratedTitle` in the adapter. A different KIND of information, so
          it sits past a separator rather than as one more attribute line.
        */}
        {property.headline ? (
          <>
            <View
              style={{
                height: 1,
                backgroundColor: theme.colors.border,
                marginVertical: spacing.md,
              }}
            />
            <Text variant="footnote" tone="secondary" numberOfLines={2}>
              {property.headline}
            </Text>
          </>
        ) : null}

        {/*
          Provenance: when it went up, and how many people have opened it.
          99acres runs the same two signals on every tuple because they answer
          what a card otherwise cannot — is this listing live, and is anyone
          else looking at it. Both are real values off the row. Quietest thing
          on the card, because it is context for a decision rather than part of
          one.
        */}
        {posted || showViews ? (
          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-md">
            {[posted ? `Posted ${posted}` : null, showViews ? `${property.views.toLocaleString('en-IN')} views` : null]
              .filter(Boolean)
              .join('  ·  ')}
          </Text>
        ) : null}
      </View>
    </PressableScale>
  );
}

export const PropertyCard = memo(PropertyCardComponent);

export { COVER_ASPECT, CARD_RADIUS } from './cardParts';
export type { CompareControlProps, SaveControlProps } from './cardParts';
