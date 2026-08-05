import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { radius } from '@/theme';
import { Image, PriceLabel, Text } from '@/ui';
import type { PropertySummary } from '../types';

/**
 * Property card.
 *
 * Design decisions, and why each one is not the obvious default:
 *
 * **No card container.** The first version wrapped this in a bordered, shadowed
 * surface. On a white background that is a white box on white, so the border
 * outlined the photo and the shadow did nothing except add noise. The photo is
 * already a solid block of colour with a hard edge; it defines the card by
 * itself. Separation between cards is carried by space, which is the cheapest
 * rung of the hierarchy ladder and the one to try before a border or a shadow.
 *
 * **One focal point.** Price is the field a buyer scans a feed by, so it takes
 * `title2` and nothing else on the card comes near that weight. The previous
 * version set price at 18/600 and the title at 16/600, which blurs into two
 * identical grey bars with nowhere for the eye to land.
 *
 * **Three groups, not five stacked lines.** Price, then place, then facts, with
 * a real gap between groups and tight spacing inside them. Every line
 * previously sat 4px from its neighbour, which reads as one undifferentiated
 * block regardless of what the words say.
 *
 * **The title is usually absent.** It is machine-composed from the same fields
 * rendered below it. See `isGeneratedTitle` in the adapter.
 *
 * Memoised, with a `useCallback` press handler, because this renders once per
 * row and an allocation here is multiplied by scroll distance.
 */

/** Exported so the skeleton matches the real geometry and the list cannot jump. */
export const COVER_HEIGHT = 210;

const COVER_STYLE = {
  width: '100%',
  height: COVER_HEIGHT,
  borderRadius: radius.lg,
} as const;

export interface PropertyCardProps {
  property: PropertySummary;
  onPress: (id: string) => void;
}

/**
 * "3 BHK · 1,250 sqft · Apartment / Flat", absent parts dropped rather than
 * blanked.
 *
 * The type comes from `propertyTypeName`, never the populated `propertyType`
 * ref: the denormalised string is correct on every live listing and the ref is
 * null or wrong on all of them.
 *
 * `bhk` arrives pre-suffixed on real data ("2 BHK", "5+ BHK"), so the suffix is
 * added only when genuinely missing.
 */
function specLine(property: PropertySummary): string {
  const parts: string[] = [];

  if (property.bhk) {
    parts.push(/bhk/i.test(property.bhk) ? property.bhk : `${property.bhk} BHK`);
  } else if (property.bedrooms) {
    parts.push(`${property.bedrooms} BHK`);
  }

  if (property.areaSqft) parts.push(`${property.areaSqft.toLocaleString('en-IN')} sqft`);

  const type = property.propertyTypeName ?? property.subcategoryName ?? property.categoryName;
  if (type) parts.push(type);

  return parts.join('  ·  ');
}

function PropertyCardComponent({ property, onPress }: PropertyCardProps) {
  const specs = specLine(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={handlePress}
      style={({ pressed }) => (pressed ? { opacity: 0.92 } : undefined)}
    >
      <View>
        {property.coverImage ? (
          <Image uri={property.coverImage} size="thumb" style={COVER_STYLE} />
        ) : (
          <View
            className="items-center justify-center bg-surface-muted"
            style={COVER_STYLE}
          >
            <Text variant="footnote" tone="muted">
              No photo
            </Text>
          </View>
        )}

        {/*
          A dark scrim chip rather than the design system's pale `Badge`. Badge
          tones are tuned against app surfaces; over a photograph they wash out
          against a bright sky and disappear entirely against a pale wall. Dark
          translucent with white text is legible over any image, in either
          scheme, which is the only requirement that matters here.
        */}
        {property.intent ? (
          <View className="absolute left-sm top-sm rounded-full bg-black/65 px-sm py-xs">
            <Text variant="caption" className="text-white">
              {property.intent === 'rent' ? 'For rent' : 'For sale'}
            </Text>
          </View>
        ) : null}
      </View>

      {/* Group 1: the number the feed is scanned by. */}
      <View className="mt-md">
        <PriceLabel
          price={property.priceRupees}
          variant="title2"
          suffix={property.intent === 'rent' ? '/month' : undefined}
        />
      </View>

      {/* Group 2: where it is, then what it is. Tight, because they belong together. */}
      <View className="mt-xs">
        {property.locationLabel ? (
          <Text variant="callout" numberOfLines={1}>
            {property.locationLabel}
          </Text>
        ) : null}

        {specs ? (
          <Text variant="footnote" tone="muted" numberOfLines={1} className="mt-xs">
            {specs}
          </Text>
        ) : null}
      </View>

      {/*
        Group 3: only reached by listings whose owner wrote a real title.
        Separated further because it is a different KIND of information, not
        another attribute.
      */}
      {property.headline ? (
        <Text variant="footnote" tone="secondary" numberOfLines={2} className="mt-sm">
          {property.headline}
        </Text>
      ) : null}
    </Pressable>
  );
}

export const PropertyCard = memo(PropertyCardComponent);
