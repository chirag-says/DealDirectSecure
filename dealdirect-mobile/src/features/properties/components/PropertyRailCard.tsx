import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Image, PressableScale, PriceLabel, Text } from '@/ui';
import type { PropertySummary } from '../types';

/**
 * The card used in every horizontal rail on Home.
 *
 * Distinct from `PropertyCard`, which is the full-width one on the browse
 * screen. They are genuinely different problems: the browse card has the whole
 * screen width and sits in a vertical list where the photo alone separates one
 * row from the next, so it needs no container. This one sits in a rail, where
 * a container is what makes a card feel like an object you could pick up.
 *
 * A shadow rather than a hairline border — changed 2026-08-14. This carried a
 * border for most of its life and the reasoning was sound at the time: on a
 * near-white page a soft shadow under every card in a rail of eight is cost
 * without effect, so an outline did the job for less. The page has since moved
 * to `palette.canvas`, several steps down the ramp, and a shadow now reads
 * properly. It matches `PropertyCard`, which matters more than either choice
 * on its own: the same object should not be built differently depending on
 * which screen it appears on.
 *
 * ---------------------------------------------------------------------------
 * THERE IS NO HEART ON THIS CARD, AND THERE SHOULD NOT BE ONE
 *
 * Removed 2026-08-14 by Chirag's decision, after being opt-in and mounted by
 * Home. Recording the reasoning here because a heart on a property card is
 * such an obvious thing to add back.
 *
 * The only "save" this backend has is `POST /properties/interested/:id`. It
 * pushes the user into the listing's `interestedUsers`, CREATES A LEAD FOR THE
 * OWNER, and EMAILS THEM the user's name, email and phone. It is also capped
 * at FIVE across the whole app, and the sixth is rejected with a 400.
 *
 * A heart means private, free, unlimited and quietly undoable. This action is
 * none of those, and putting it behind a heart meant a user could spend one of
 * five enquiries — and hand a stranger their phone number — with a thumb
 * brushing the corner of a photo, on the app's busiest screen.
 *
 * Every surface that offers this action now offers it the same way: a labelled
 * button with a consequence line under it, on the detail screen where there is
 * room to say what happens. See `features/properties/interest.ts` and
 * `DetailActions.tsx`. A rail card has no room for that sentence, which is the
 * real reason it should not carry the control.
 */

const IMAGE_HEIGHT = 180;

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
  Partial<
    Pick<
      PropertySummary,
      'bhk' | 'bedrooms' | 'propertyTypeName' | 'subcategoryName' | 'areaSqft' | 'bathrooms'
    >
  >;

export interface PropertyRailCardProps {
  property: RailProperty;
  /** Supplied by `Rail`, so the card and the snap interval cannot disagree. */
  width: number;
  onPress: (id: string) => void;
}

/** "3 BHK Apartment", the card's second-most scanned fact after price. */
function typeLine(property: RailProperty): string | undefined {
  const bhk = property.bhk
    ? (/bhk/i.test(property.bhk) ? property.bhk : `${property.bhk} BHK`)
    : property.bedrooms
      ? `${property.bedrooms} BHK`
      : undefined;

  // `propertyTypeName` and never the populated `propertyType` ref: the
  // denormalised string is correct on every live listing, the ref is null or
  // points at the wrong document on all of them.
  const type = property.propertyTypeName ?? property.subcategoryName;

  return [bhk, type].filter(Boolean).join(' ') || undefined;
}

/** One icon-and-label pair on the card's bottom row. */
function MetaFact({
  icon,
  label,
  theme,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  theme: ReturnType<typeof useTheme>;
}) {
  return (
    <View className="flex-row items-center" style={{ gap: spacing.xs + 1 }}>
      <Ionicons name={icon} size={13} color={theme.colors.textMuted} />
      <Text variant="caption" tone="muted" numberOfLines={1}>
        {label}
      </Text>
    </View>
  );
}

function PropertyRailCardComponent({
  property,
  width,
  onPress,
}: PropertyRailCardProps) {
  const theme = useTheme();
  const type = typeLine(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  return (
    <PressableScale
      accessibilityLabel={property.title}
      onPress={handlePress}
      style={{
        width,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        // Shadow, not a border — matched to `PropertyCard` so the same object
        // does not change its construction between Home and the browse list.
        // The page is dark enough now (`palette.canvas`) for a shadow to read;
        // when this card was written it was not, which is why it outlined
        // itself instead.
        shadowColor: '#000',
        shadowOpacity: 0.07,
        shadowRadius: 12,
        shadowOffset: { width: 0, height: 4 },
        elevation: 3,
        overflow: 'hidden',
      }}
    >
      <View style={{ height: IMAGE_HEIGHT }}>
        {property.coverImage ? (
          <Image uri={property.coverImage} size="thumb" style={{ width: '100%', height: '100%' }} />
        ) : (
          <View className="h-full w-full items-center justify-center bg-surface-muted">
            <Ionicons name="image-outline" size={26} color={theme.colors.textMuted} />
            <Text variant="caption" tone="muted" className="mt-xs">
              No photo
            </Text>
          </View>
        )}

        {/*
          Near-black rather than a colour-coded fill. An earlier version tinted
          this green for sale and blue for rent, which spent two more hues on a
          screen where red is the only accent. The label carries the
          distinction; the fill exists only so it survives whatever the owner
          photographed behind it, and dark is the one value that works over a
          bright sky and a white wall alike.
        */}
        {property.intent ? (
          <View
            className="absolute"
            style={{
              left: spacing.md,
              top: spacing.md,
              paddingHorizontal: spacing.sm + 2,
              paddingVertical: spacing.xs,
              borderRadius: radius.sm,
              backgroundColor: 'rgba(10,10,10,0.78)',
            }}
          >
            <Text variant="overline" style={{ color: '#FFFFFF' }}>
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

        {type ? (
          <Text variant="bodyEmphasis" numberOfLines={1} className="mt-xs">
            {type}
          </Text>
        ) : null}

        <View className="mt-xs flex-row items-center" style={{ gap: spacing.xs }}>
          <Ionicons name="location-outline" size={13} color={theme.colors.brand} />
          <Text variant="footnote" tone="secondary" numberOfLines={1} className="flex-1">
            {property.locationLabel}
          </Text>
        </View>

        {/*
          Each fact gets its own glyph rather than sharing one line of text,
          because area and bathrooms are scanned independently — a buyer
          filtering on size never reads the bath count and vice versa. Absent
          fields drop out entirely rather than rendering a dash, so a listing
          that never captured its area does not advertise the omission.
        */}
        {property.areaSqft || property.bathrooms ? (
          <View className="mt-sm flex-row items-center" style={{ gap: spacing.md }}>
            {property.areaSqft ? (
              <MetaFact
                icon="expand-outline"
                label={`${property.areaSqft.toLocaleString('en-IN')} sq.ft`}
                theme={theme}
              />
            ) : null}

            {property.areaSqft && property.bathrooms ? (
              <View
                style={{
                  width: 3,
                  height: 3,
                  borderRadius: radius.full,
                  backgroundColor: theme.colors.textMuted,
                }}
              />
            ) : null}

            {property.bathrooms ? (
              <MetaFact
                icon="water-outline"
                label={`${property.bathrooms} Bath${property.bathrooms === 1 ? '' : 's'}`}
                theme={theme}
              />
            ) : null}
          </View>
        ) : null}
      </View>
    </PressableScale>
  );
}

/** Memoised: this renders once per rail item, multiplied by every rail. */
export const PropertyRailCard = memo(PropertyRailCardComponent);
