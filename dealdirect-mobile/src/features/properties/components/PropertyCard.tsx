import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { relativeDay } from '@/lib';
import { radius, spacing, useTheme } from '@/theme';
import { formatRatePerSqft, Image, PressableScale, PriceLabel, Text } from '@/ui';
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
 * **Four groups, not seven stacked lines.** Price and its unit rate, then
 * place, then the fact row, then provenance — with a real gap between groups
 * and tight spacing inside them. Every line previously sat 4px from its
 * neighbour, which reads as one undifferentiated block regardless of what the
 * words say. Each group has its own note at the point it is rendered.
 *
 * **Nothing here is invented data.** The photo count, the unit rate, the posted
 * date and the view count are all either fields on the row or arithmetic over
 * two of them. The reference cards this was measured against carry a fifth
 * signal we cannot honestly match — 99acres' "Verified", Square Yards' RERA
 * badge — because our backend has no verification state for a listing. An
 * unearned trust badge is worse than none.
 *
 * **The title is usually absent.** It is machine-composed from the same fields
 * rendered below it. See `isGeneratedTitle` in the adapter.
 *
 * Memoised, with a `useCallback` press handler, because this renders once per
 * row and an allocation here is multiplied by scroll distance.
 */

/** Exported so the skeleton matches the real geometry and the list cannot jump. */
export const COVER_HEIGHT = 210;

/**
 * Below this, the view count is suppressed rather than shown.
 *
 * Ten is where the number starts carrying information. Under it the figure is
 * as likely to be the owner reloading their own listing as it is to be demand,
 * and printing "2 views" tells a buyer the listing is ignored — which may be
 * true, but it is not a fact this card has the standing to assert on the
 * strength of a counter that also counts crawlers.
 */
const MEANINGFUL_VIEW_COUNT = 10;

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
 * The card's fact row: configuration, area, type — each as an icon and a value.
 *
 * ---------------------------------------------------------------------------
 * WHY ICONS REPLACED "3 BHK · 1,250 sqft · Apartment / Flat"
 *
 * The dot-joined string was one run of small grey text, which means the reader
 * has to parse it left to right to find the field they care about, and at a
 * glance it reads as a single texture rather than as three facts. Square Yards
 * and 99acres both put a labelled icon on each attribute on their results
 * cards, and it is not decoration: the icon is what lets the eye jump straight
 * to the area figure without reading the two values before it.
 *
 * No text labels under the values, though, which is where the reference cards
 * spend space we do not have. Square Yards' tuple is 495pt tall and can afford
 * "Area Built-up Area" under 2,220; ours is around 380 and the icons carry the
 * same meaning in a fifth of the height. The full labelled table is on the
 * detail screen, where there is room for it.
 *
 * The type comes from `propertyTypeName`, never the populated `propertyType`
 * ref: the denormalised string is correct on every live listing and the ref is
 * null or wrong on all of them.
 *
 * `bhk` arrives pre-suffixed on real data ("2 BHK", "5+ BHK"), so the suffix is
 * added only when genuinely missing.
 */
interface Spec {
  icon: keyof typeof Ionicons.glyphMap;
  value: string;
}

function specs(property: PropertySummary): Spec[] {
  const items: Spec[] = [];

  if (property.bhk) {
    items.push({
      icon: 'bed-outline',
      value: /bhk|rk/i.test(property.bhk) ? property.bhk : `${property.bhk} BHK`,
    });
  } else if (property.bedrooms) {
    items.push({ icon: 'bed-outline', value: `${property.bedrooms} BHK` });
  }

  if (property.areaSqft) {
    items.push({
      icon: 'resize-outline',
      value: `${property.areaSqft.toLocaleString('en-IN')} sqft`,
    });
  }

  const type = property.propertyTypeName ?? property.subcategoryName ?? property.categoryName;
  if (type) items.push({ icon: 'home-outline', value: type });

  return items;
}

/**
 * The row itself. `flexShrink` on every cell rather than a fixed width: the
 * type name runs from "Villa" to "Independent House / Villa" and the row has to
 * absorb that without pushing the area figure off the card.
 */
function SpecRow({ items, compact = false }: { items: Spec[]; compact?: boolean }) {
  const theme = useTheme();
  if (items.length === 0) return null;

  return (
    <View className="flex-row items-center" style={{ gap: compact ? spacing.md : spacing.base }}>
      {items.map((item) => (
        <View key={item.icon} className="flex-row items-center" style={{ flexShrink: 1 }}>
          <Ionicons
            name={item.icon}
            size={compact ? 13 : 15}
            color={theme.colors.textMuted}
          />
          <Text
            variant={compact ? 'caption' : 'footnote'}
            tone="secondary"
            numberOfLines={1}
            className="ml-xs"
          >
            {item.value}
          </Text>
        </View>
      ))}
    </View>
  );
}

function PropertyCardComponent({ property, onPress, compare }: PropertyCardProps) {
  const theme = useTheme();
  const facts = specs(property);
  const handlePress = useCallback(() => onPress(property.id), [onPress, property.id]);

  /*
   * The unit rate, and why only on sales.
   *
   * "₹6,800 / sqft" is the number that makes two sale listings comparable, and
   * it is how every portal prints them. On a RENTAL the same arithmetic gives
   * "₹36 / sqft", which is a monthly figure that reads as a purchase price
   * unless it carries a "/month" the card has no room for. Commercial leasing
   * does quote rent per sqft per month; residential does not, and this card
   * cannot tell which it is looking at with enough confidence to switch the
   * label. So sales only, where the unit is unambiguous.
   */
  const rate = property.intent === 'rent' ? null : formatRatePerSqft(property.priceRupees, property.areaSqft);

  const posted = relativeDay(property.createdAt);

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

        {/*
          THE PHOTO COUNT.

          Two jobs, and the second is the one that earns it a place. It says how
          much there is to look at, which is what makes a listing with nine
          photos worth opening over one with two — the strongest quality signal
          a card can carry when everything else on it is owner-supplied text.
          And it tells the user the hero image is swipeable on the next screen,
          which nothing else here does.

          Bottom-right rather than bottom-left, where Square Yards puts it: our
          intent chip is top-left and our compare control top-right, so the
          remaining free corner is this one. Same dark translucent treatment as
          the intent chip, for the same reason — see its note above.
        */}
        {property.imageCount > 1 ? (
          <View className="absolute bottom-sm right-sm flex-row items-center rounded-full bg-black/65 px-sm py-xs">
            <Ionicons name="images-outline" size={11} color="#FFFFFF" />
            <Text variant="caption" className="ml-xs text-white">
              {property.imageCount}
            </Text>
          </View>
        ) : null}
      </View>

      <View style={{ padding: spacing.base }}>
        {/*
          Group 1: the number the feed is scanned by, and the number that makes
          it comparable to the one above it. The rate sits on the SAME line,
          right-aligned and two steps down the type scale — it is a footnote to
          the price rather than a second price, and putting it on its own line
          would give it a whole row of prominence it has not earned.
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

        {/* Group 2: where it is, then what it is. Tight — they belong together. */}
        {property.locationLabel ? (
          <View className="mt-xs flex-row items-center">
            <Ionicons name="location-outline" size={14} color={theme.colors.textMuted} />
            <Text variant="callout" numberOfLines={1} className="ml-xs flex-1">
              {property.locationLabel}
            </Text>
          </View>
        ) : null}

        {facts.length > 0 ? (
          <View className="mt-sm">
            <SpecRow items={facts} />
          </View>
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

        {/*
          THE PROVENANCE LINE.

          When it went up, and how many people have opened it. 99acres runs the
          same two signals on every tuple ("Posted today by owner", "3 people
          already contacted since last week") because they answer the question a
          card otherwise cannot: is this listing live, and is anyone else
          looking at it.

          Both are real values off the row rather than engagement theatre.
          `createdAt` is the document's own timestamp and `views` is the
          backend's own counter, incremented once per detail-screen open — see
          `PropertySummary.views`. Neither is inflated, and neither is shown
          when it would be noise: views only past a threshold, because "1 view"
          on a listing the reader is about to become the second of says nothing
          and reads as an admission that nobody is interested.

          Quietest thing on the card, in `caption`/muted. It is context for a
          decision, not part of one.
        */}
        {posted || property.views >= MEANINGFUL_VIEW_COUNT ? (
          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-sm">
            {[posted ? `Posted ${posted}` : null, property.views >= MEANINGFUL_VIEW_COUNT ? `${property.views.toLocaleString('en-IN')} views` : null]
              .filter(Boolean)
              .join('  ·  ')}
          </Text>
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
  // Two, not three. The row gives its text about 220pt and the third spec
  // would truncate the two that matter rather than fitting beside them.
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
      <View>
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

        {/* Same signal as the card's, sized for a 108pt thumbnail: the count
            alone, no icon. At this size the icon and the digit compete for the
            same six points and neither wins. */}
        {property.imageCount > 1 ? (
          <View
            className="absolute bottom-xs left-xs rounded-full bg-black/65"
            style={{ paddingHorizontal: 6, paddingVertical: 1 }}
          >
            <Text variant="caption" className="text-white">
              {property.imageCount}
            </Text>
          </View>
        ) : null}
      </View>

      <View style={{ flex: 1, padding: spacing.md, justifyContent: 'center' }}>
        <View className="flex-row items-baseline">
          <PriceLabel
            price={property.priceRupees}
            variant="bodyEmphasis"
            suffix={property.intent === 'rent' ? '/month' : undefined}
          />
          {/* The whole point of the compact density is comparing ten listings
              at once, which is exactly when the unit rate is worth most. */}
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
          <View className="mt-xs">
            <SpecRow items={facts} compact />
          </View>
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
