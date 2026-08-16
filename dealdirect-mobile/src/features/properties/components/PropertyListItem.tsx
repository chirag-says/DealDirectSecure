import { memo, useCallback } from 'react';
import { View } from 'react-native';

import { spacing, touchTarget, useTheme } from '@/theme';
import { formatRatePerSqft, PressableScale, PriceLabel, Text } from '@/ui';
import type { PropertySummary } from '../types';
import {
  cardShadow,
  Cover,
  IntentBadge,
  PhotoCount,
  ROW_RADIUS,
  SaveControl,
  SpecRow,
  specs,
  THUMB_ASPECT,
  THUMB_WIDTH_RATIO,
  type SaveControlProps,
} from './cardParts';

/**
 * The compact row, for scanning many listings at once.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS STRUCTURALLY WRONG WITH THE ONE THIS REPLACES
 *
 * The previous `PropertyRow` was the feed card's markup at a smaller size, and
 * every problem it had came from that rather than from its styling:
 *
 *  - **The thumbnail was a fixed 108pt square** while the row's height was
 *    whatever its text came to. On a listing with two spec lines the photo was
 *    taller than the content and left a band of empty card below it; on one
 *    with a long location it was shorter and left a notch above and below. Row
 *    heights and image heights therefore both varied, independently, down the
 *    list — which is exactly what the screenshot shows.
 *  - **108pt is 29% of a 375pt screen and 25% of a 430pt one**, so the split
 *    between photo and text changed per device.
 *  - **The intent chip was absolutely positioned over the TEXT column**, top
 *    right, where it collided with the per-sqft rate and cost a full line of
 *    the three the row has.
 *  - **The photo count sat bottom-left of the thumbnail**, the opposite corner
 *    from the feed card's, so the same signal moved when the view changed.
 *
 * This row fixes the class, not the instances: the photo is a SHARE of the row
 * width at a fixed aspect, and it stretches to the row's height, so every row
 * in the list is the same height and every thumbnail is the same shape whatever
 * the text does. Overlays go where `cardParts` says they go, which is where the
 * feed card puts them.
 *
 * ---------------------------------------------------------------------------
 * WHAT EARNS A LINE HERE
 *
 * Three lines of text and no more, because the whole reason to switch to this
 * density is fitting three times as many results on a screen:
 *
 *   1. price, with the per-sqft rate beside it — the comparison axis
 *   2. location
 *   3. the two strongest specs
 *
 * The type name is the third spec on the feed card and the first thing dropped
 * here: at this width a third cell truncates the two that matter rather than
 * fitting beside them.
 *
 * Offering this density is also the cheapest accessibility win on the screen.
 * It fits roughly three times as many results per viewport, which matters most
 * to exactly the users who have enlarged their system text and see fewest.
 */

function PropertyListItemComponent({
  property,
  onPress,
  save,
}: {
  property: PropertySummary;
  onPress: (id: string) => void;
  save?: SaveControlProps;
}) {
  const theme = useTheme();
  const facts = specs(property).slice(0, 2);
  const rate =
    property.intent === 'rent' ? null : formatRatePerSqft(property.priceRupees, property.areaSqft);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={handlePress}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        // `stretch`, and this one word is most of the fix: the photo column
        // takes the row's height rather than the row taking the photo's.
        alignItems: 'stretch',
        borderRadius: ROW_RADIUS,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        ...cardShadow,
      }}
    >
      {/*
        A percentage of the row, not a point value, so the split holds from a
        320pt phone to a 430pt one. `aspectRatio` on the photo sets the row's
        minimum height; the text column sets the rest, and whichever is taller
        wins for both because the container stretches.
      */}
      <View style={{ width: `${THUMB_WIDTH_RATIO * 100}%` }}>
        <Cover uri={property.coverImage} aspectRatio={THUMB_ASPECT} iconSize={20} />

        <View className="absolute left-0 top-0" style={{ padding: spacing.sm }}>
          <IntentBadge intent={property.intent} compact />
        </View>

        <View className="absolute bottom-0 right-0" style={{ padding: spacing.sm }}>
          <PhotoCount count={property.imageCount} compact />
        </View>
      </View>

      <View
        style={{
          flex: 1,
          paddingVertical: spacing.md,
          paddingLeft: spacing.md,
          // Leaves room for the save control's 44pt target without the text
          // running under it. `pr` alone would not: the control is absolutely
          // positioned, so the reservation has to be explicit.
          paddingRight: save ? touchTarget.min : spacing.md,
          justifyContent: 'center',
        }}
      >
        {/*
          The price never wraps and the rate yields to it. Row height is set by
          the 1:1 thumbnail, and the only text here that could out-grow it is a
          long price beside a long rate - which is what would make one unusual
          listing change the height of a row in an otherwise uniform list.
        */}
        <View className="flex-row items-baseline">
          <PriceLabel
            price={property.priceRupees}
            variant="bodyEmphasis"
            numberOfLines={1}
            suffix={property.intent === 'rent' ? '/month' : undefined}
          />
          {/* The point of this density is comparing ten listings at once,
              which is exactly when the unit rate is worth most. */}
          {rate ? (
            <Text variant="caption" tone="muted" numberOfLines={1} className="ml-sm flex-1">
              {rate}
            </Text>
          ) : null}
        </View>

        {property.locationLabel ? (
          <Text variant="footnote" numberOfLines={1} className="mt-xs">
            {property.locationLabel}
          </Text>
        ) : null}

        {facts.length > 0 ? (
          <View className="mt-sm">
            <SpecRow items={facts} compact />
          </View>
        ) : null}
      </View>

      {/*
        Bottom-right of the TEXT column rather than over the photo. At this
        thumbnail size a 34pt disc covers a third of the image, and the row's
        own right edge is both closer to the thumb and free.
      */}
      {save ? (
        <View className="absolute bottom-0 right-0">
          <SaveControl {...save} bare tint={theme.colors.textMuted} />
        </View>
      ) : null}
    </PressableScale>
  );
}

export const PropertyListItem = memo(PropertyListItemComponent);
