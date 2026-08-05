import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { View } from 'react-native';

import { elevation, radius, spacing, useTheme } from '@/theme';
import { Image, PressableScale, PriceLabel, Scrim, Text } from '@/ui';
import type { PropertySummary } from '../types';

/**
 * The card used in every horizontal rail on Home.
 *
 * Distinct from `PropertyCard`, which is the full-width one on the browse
 * screen. They are genuinely different problems: the browse card has the whole
 * screen width and sits in a vertical list where the photo alone separates one
 * row from the next, so it needs no container. This one sits in a rail on a
 * tinted page, where a container is what makes a card feel like an object you
 * could pick up.
 *
 * That container only works because the page background moved off pure white
 * (see `theme/colors.ts`). On the old `#FFFFFF` page this same card needed a
 * grey border to be visible at all, which is what the ported original did, and
 * a screenful of hairline rectangles is what made it read as an admin panel.
 * Now the surface is simply brighter than the page and a soft shadow finishes
 * it. Same card, no border.
 *
 * ---------------------------------------------------------------------------
 * NO FAVOURITE BUTTON, AND THAT IS DELIBERATE
 *
 * The card this is ported from has a heart in the top-right corner. It calls
 * `POST /api/users/save-property`. That route does not exist — not in
 * `userRoutes.js`, not anywhere in the backend. The call fails into a
 * `console.error` and the heart silently never sticks, so the control is a
 * promise the product cannot keep.
 *
 * A control whose appearance contradicts its behaviour is the worst thing on a
 * screen: everything else has to be re-examined once the user finds one. So
 * there is no heart here until there is an endpoint behind it. Adding it back
 * is one prop and one mutation on the day that ships.
 */

const IMAGE_HEIGHT = 168;

/**
 * The fields this card actually draws, and nothing more.
 *
 * Deliberately NOT `PropertySummary`. Two different things feed these rails: a
 * live `PropertySummary` from the API, and a `ViewedProperty` replayed from
 * disk, which stores only the handful of fields needed to redraw the card (see
 * `recentlyViewed.ts` for why it snapshots instead of refetching).
 *
 * Typing the prop as the full summary would force the history row to fabricate
 * a dozen fields it never captured, or to cast the difference away. A
 * structural subset lets both satisfy the same contract honestly, and it
 * documents the card's real dependencies: adding a field here is a deliberate
 * act that immediately shows which callers cannot supply it.
 */
export type RailProperty = Pick<
  PropertySummary,
  'id' | 'title' | 'priceRupees' | 'intent' | 'coverImage' | 'locationLabel'
> &
  Partial<Pick<PropertySummary, 'bhk' | 'bedrooms' | 'propertyTypeName' | 'subcategoryName'>>;

export interface PropertyRailCardProps {
  property: RailProperty;
  /** Supplied by `Rail`, so the card and the snap interval cannot disagree. */
  width: number;
  onPress: (id: string) => void;
}

/** "3 BHK · Apartment / Flat", absent parts dropped rather than blanked. */
function specLine(property: RailProperty): string {
  const parts: string[] = [];

  if (property.bhk) {
    parts.push(/bhk/i.test(property.bhk) ? property.bhk : `${property.bhk} BHK`);
  } else if (property.bedrooms) {
    parts.push(`${property.bedrooms} BHK`);
  }

  // `propertyTypeName` and never the populated `propertyType` ref: the
  // denormalised string is correct on every live listing, the ref is null or
  // points at the wrong document on all of them.
  const type = property.propertyTypeName ?? property.subcategoryName;
  if (type) parts.push(type);

  return parts.join('  ·  ');
}

function PropertyRailCardComponent({ property, width, onPress }: PropertyRailCardProps) {
  const theme = useTheme();
  const specs = specLine(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  return (
    <PressableScale
      accessibilityLabel={property.title}
      onPress={handlePress}
      style={{
        width,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        shadowColor: '#000',
        shadowOpacity: elevation.card.shadowOpacity,
        shadowRadius: elevation.card.shadowRadius,
        shadowOffset: { width: 0, height: elevation.card.shadowOffsetY },
        elevation: elevation.card.elevation,
      }}
    >
      <View style={{ height: IMAGE_HEIGHT }}>
        {property.coverImage ? (
          <Image uri={property.coverImage} size="thumb" style={{ width: '100%', height: '100%' }} />
        ) : (
          <View
            className="h-full w-full items-center justify-center bg-surface-muted"
          >
            <Ionicons name="image-outline" size={26} color={theme.colors.textMuted} />
            <Text variant="caption" tone="muted" className="mt-xs">
              No photo
            </Text>
          </View>
        )}

        {/*
          A gradient rather than a solid chip behind the badge. Listing photos
          are unretouched owner uploads: a bright sky, a white wall and a night
          shot all appear in the same rail, and a fixed-opacity chip tuned for
          the worst of those is far too heavy on the rest.
        */}
        {property.intent ? <Scrim variant="tile" /> : null}

        {property.intent ? (
          <View
            className="absolute flex-row items-center"
            style={{
              left: spacing.md,
              bottom: spacing.md,
              paddingHorizontal: spacing.sm + 2,
              paddingVertical: spacing.xs,
              borderRadius: radius.full,
              // Intent is the one attribute that changes what the price MEANS
              // (monthly versus total), so it is the one badge that earns
              // colour rather than a neutral fill.
              backgroundColor:
                property.intent === 'rent' ? theme.colors.accent : theme.colors.success,
            }}
          >
            <Text variant="overline" style={{ color: theme.colors.textOnAccent }}>
              {property.intent === 'rent' ? 'FOR RENT' : 'FOR SALE'}
            </Text>
          </View>
        ) : null}
      </View>

      <View style={{ padding: spacing.md }}>
        {/*
          Price first and largest. It is the field a feed is scanned by, and
          the ported original set it below a bolded title, which produced two
          competing dark bars with nowhere for the eye to land.
        */}
        <PriceLabel
          price={property.priceRupees}
          variant="title3"
          suffix={property.intent === 'rent' ? '/mo' : undefined}
        />

        <View className="mt-xs flex-row items-center" style={{ gap: spacing.xs }}>
          <Ionicons name="location-outline" size={13} color={theme.colors.brand} />
          <Text variant="footnote" tone="secondary" numberOfLines={1} className="flex-1">
            {property.locationLabel}
          </Text>
        </View>

        {specs ? (
          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-sm">
            {specs}
          </Text>
        ) : null}
      </View>
    </PressableScale>
  );
}

/** Memoised: this renders once per rail item, multiplied by every rail. */
export const PropertyRailCard = memo(PropertyRailCardComponent);
