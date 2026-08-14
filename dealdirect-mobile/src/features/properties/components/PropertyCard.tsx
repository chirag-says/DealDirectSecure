import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Image, PressableScale, PriceLabel, Text } from '@/ui';
import type { PropertySummary } from '../types';

/**
 * Property card.
 *
 * Two shapes ship from this file: `PropertyCard` (photo on top, full width)
 * and `PropertyRow` (compact, photo left). The Properties screen switches
 * between them; see `PropertyRow`'s own note for why both exist.
 *
 * Design decisions, and why each one is not the obvious default:
 *
 * **A card container — but only since the page got darker.** This deliberately
 * had NO container for most of its life, and that was correct then: the page
 * was pure white, so a white card was invisible and its border was the only
 * visible thing. The page now sits on `palette.canvas`, so a white surface
 * separates by being brighter, which is the whole point of that colour. The
 * reasoning is preserved rather than deleted because it explains what to
 * revisit if the background ever goes back up the ramp.
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
} as const;

export interface PropertyCompareProps {
  selected: boolean;
  /** False when a third pick would exceed `MAX_COMPARE` or clash with the
   *  property type already anchoring the selection. The chip still renders,
   *  disabled, rather than disappearing — see `features/search/compare.ts`. */
  disabled: boolean;
  onToggle: () => void;
}

export interface PropertyCardProps {
  property: PropertySummary;
  onPress: (id: string) => void;
  /** Renders a selectable compare chip over the photo when present. Search
   *  results is the only screen that ever passes this. */
  compare?: PropertyCompareProps;
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

function PropertyCardComponent({ property, onPress, compare }: PropertyCardProps) {
  const theme = useTheme();
  const specs = specLine(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  /*
   * A REAL CARD NOW — changed 2026-08-14.
   *
   * The note above this component argued against a container, and it was right
   * at the time: the page was pure white, so a white card was invisible and
   * its border was the only thing you could see. That is no longer true. The
   * page sits on `palette.canvas`, several steps down the ramp, so a white
   * surface separates by being brighter — which is what the colour change was
   * for. The photo no longer has to do the job of the card on its own.
   *
   * Radius 14 (`radius.lg`), matching what Airbnb uses on a property card and
   * what §4 of the visual system says a card of this size should take.
   *
   * Still no heart. That is not an oversight and not a style choice: saving on
   * this backend creates a Lead, emails the owner, hands over the user's
   * contact details and is capped at five. See `features/properties/interest.ts`.
   * A heart would promise private, free and unlimited, and it is none of them.
   */
  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={handlePress}
      activeScale={0.985}
      style={{
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        shadowColor: '#000',
        shadowOpacity: 0.07,
        shadowRadius: 12,
        shadowOffset: { width: 0, height: 4 },
        elevation: 3,
      }}
    >
      <View>
        {property.coverImage ? (
          <Image uri={property.coverImage} size="thumb" style={COVER_STYLE} />
        ) : (
          <View
            className="items-center justify-center bg-surface-muted"
            style={COVER_STYLE}
          >
            <Ionicons name="image-outline" size={26} color={theme.colors.textMuted} />
            <Text variant="footnote" tone="muted" className="mt-xs">
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

        {/*
          A separate control from the card's own press target — tapping it
          toggles comparison, tapping anywhere else on the card still opens
          the listing. `hitSlop` compensates for a chip this small sitting
          over a photo other taps also want.
        */}
        {compare ? (
          <Pressable
            accessibilityRole="checkbox"
            accessibilityState={{ checked: compare.selected, disabled: compare.disabled }}
            accessibilityLabel={compare.selected ? 'Remove from comparison' : 'Add to comparison'}
            hitSlop={8}
            disabled={compare.disabled && !compare.selected}
            onPress={compare.onToggle}
            className="absolute right-sm top-sm h-8 w-8 items-center justify-center rounded-full bg-black/65"
            style={({ pressed }) => (pressed ? { opacity: 0.8 } : undefined)}
          >
            <Ionicons
              name={compare.selected ? 'checkmark-circle' : 'ellipse-outline'}
              size={20}
              color={
                compare.selected
                  ? theme.colors.accent
                  : compare.disabled
                    ? 'rgba(255,255,255,0.4)'
                    : '#FFFFFF'
              }
            />
          </Pressable>
        ) : null}
      </View>

      <View style={{ padding: spacing.base }}>
        {/* Group 1: the number the feed is scanned by. */}
        <PriceLabel
          price={property.priceRupees}
          variant="title2"
          suffix={property.intent === 'rent' ? '/month' : undefined}
        />

        {/* Group 2: where it is, then what it is. Tight — they belong together. */}
        {property.locationLabel ? (
          <View className="mt-xs flex-row items-center">
            <Ionicons name="location-outline" size={14} color={theme.colors.textMuted} />
            <Text variant="callout" numberOfLines={1} className="ml-xs flex-1">
              {property.locationLabel}
            </Text>
          </View>
        ) : null}

        {specs ? (
          <Text variant="footnote" tone="muted" numberOfLines={1} className="mt-xs">
            {specs}
          </Text>
        ) : null}

        {/*
          Group 3: only reached by listings whose owner wrote a real title —
          most are machine-composed from the fields already shown above. A
          different KIND of information, so it sits past a separator rather
          than as one more attribute line.
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
      </View>
    </PressableScale>
  );
}

export const PropertyCard = memo(PropertyCardComponent);

/**
 * The compact variant, for the Properties screen's list mode.
 *
 * ---------------------------------------------------------------------------
 * WHY BOTH SHAPES EXIST
 *
 * The two are not a style preference, they answer different questions. A photo
 * that fills the width is what you want when the picture is deciding for you —
 * browsing, discovering, "do I like this". A horizontal row gives far more of
 * its area to structured text, which is what you want when price, size and
 * location are what you are comparing across ten listings.
 *
 * Offering the toggle is also the cheapest accessibility win on the screen:
 * the compact row fits roughly three times as many results per viewport, which
 * matters most to exactly the users who have enlarged their system text and
 * see fewest rows.
 */
export const ROW_HEIGHT = 108;

function PropertyRowComponent({ property, onPress }: Omit<PropertyCardProps, 'compare'>) {
  const theme = useTheme();
  const specs = specLine(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={handlePress}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        shadowColor: '#000',
        shadowOpacity: 0.06,
        shadowRadius: 10,
        shadowOffset: { width: 0, height: 3 },
        elevation: 2,
      }}
    >
      {property.coverImage ? (
        <Image
          uri={property.coverImage}
          size="thumb"
          style={{ width: ROW_HEIGHT, height: ROW_HEIGHT }}
        />
      ) : (
        <View
          className="items-center justify-center bg-surface-muted"
          style={{ width: ROW_HEIGHT, height: ROW_HEIGHT }}
        >
          <Ionicons name="image-outline" size={22} color={theme.colors.textMuted} />
        </View>
      )}

      <View style={{ flex: 1, padding: spacing.md, justifyContent: 'center' }}>
        <PriceLabel
          price={property.priceRupees}
          variant="bodyEmphasis"
          suffix={property.intent === 'rent' ? '/month' : undefined}
        />

        {property.locationLabel ? (
          <Text variant="footnote" numberOfLines={1} className="mt-xs">
            {property.locationLabel}
          </Text>
        ) : null}

        {specs ? (
          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-xs">
            {specs}
          </Text>
        ) : null}
      </View>

      {property.intent ? (
        <View
          className="absolute right-sm top-sm rounded-full px-sm"
          style={{ paddingVertical: 2, backgroundColor: theme.colors.surfaceMuted }}
        >
          <Text variant="caption" tone="secondary">
            {property.intent === 'rent' ? 'Rent' : 'Sale'}
          </Text>
        </View>
      ) : null}
    </PressableScale>
  );
}

export const PropertyRow = memo(PropertyRowComponent);
