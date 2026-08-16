import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, touchTarget, useTheme } from '@/theme';
import { Image, PressableScale, Text } from '@/ui';
import type { PropertySummary } from '../types';

/**
 * The pieces every property card is built from.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE ARE FACTORED OUT
 *
 * Three surfaces render a property: the feed card, the compact list row, and
 * the Saved card. Before this file they shared nothing — each re-declared its
 * own photo container, its own intent badge, its own photo-count chip, at
 * different sizes, with different insets, and in one case at the opposite
 * corner. That is why the list view and the feed view read as two apps: not
 * because the layouts differ, which they should, but because the same three
 * signals were drawn three different ways.
 *
 * Layout belongs to each card. These own what a signal LOOKS like, once.
 *
 * ---------------------------------------------------------------------------
 * THE OVERLAY CORNERS ARE ASSIGNED, NOT NEGOTIATED
 *
 *   top-left      intent — "For sale" / "For rent"
 *   top-right     the one action: save, or compare when compare mode is on
 *   bottom-right  photo count
 *
 * Fixed across all three cards, so a user who learns where the save control is
 * on the feed does not have to find it again in the list. The bottom-left
 * corner is deliberately empty: it is where a caption would sit if the card
 * ever grows one, and an empty corner is what stops the photo reading as a
 * dashboard.
 */

/**
 * A ratio, NOT a height.
 *
 * The old card fixed the cover at 210pt, which meant the photo was 1.72:1 on a
 * 375pt phone and 2.1:1 on a 430pt one — the same card, visibly different
 * proportions per device, and different again beside a skeleton computed from
 * the same constant. 3:2 is the standard photographic ratio and it holds on
 * every width.
 */
export const COVER_ASPECT = 3 / 2;

/**
 * How far every overlay sits from the photo's edge.
 *
 * One value, and the two overlay kinds reach it differently, which is the
 * whole reason it is computed rather than typed twice. A badge is its own
 * bounding box, so it just takes this as a margin. A control is a 44pt target
 * wrapped around a 34pt disc, so its box has to sit CLOSER to the edge by half
 * the difference for the disc to land on the same line as the badge.
 *
 * Getting this wrong is invisible in isolation and obvious side by side: the
 * badge at 12 and the disc at 5 is what makes a card look assembled rather
 * than laid out.
 */
export const OVERLAY_INSET = spacing.md;

/** The visible disc inside a `touchTarget.min` box. */
const CONTROL_DISC = 34;

export const CONTROL_INSET = OVERLAY_INSET - (touchTarget.min - CONTROL_DISC) / 2;

/** The compact row's thumbnail, as a share of the row width. */
export const THUMB_WIDTH_RATIO = 0.32;
export const THUMB_ASPECT = 1;

/**
 * Dark translucent, never the design system's `Badge`.
 *
 * Badge tones are tuned against app surfaces. Over a photograph a pale chip
 * washes out against a bright sky and vanishes against a pale wall; dark
 * translucent with white text is legible over any image in either scheme,
 * which is the only requirement an overlay has.
 */
export function IntentBadge({
  intent,
  compact = false,
}: {
  intent: PropertySummary['intent'];
  compact?: boolean;
}) {
  if (!intent) return null;

  return (
    <View
      className="rounded-full bg-black/65"
      style={{
        paddingHorizontal: compact ? spacing.sm : spacing.md,
        paddingVertical: compact ? 2 : spacing.xs,
      }}
    >
      <Text variant="caption" className="text-white">
        {intent === 'rent' ? 'For rent' : 'For sale'}
      </Text>
    </View>
  );
}

/**
 * How much there is to look at.
 *
 * Two jobs, and the second earns it the space: it is the strongest quality
 * signal a card can carry when everything else on it is owner-supplied text,
 * and it says the hero image is swipeable on the next screen, which nothing
 * else here does.
 */
export function PhotoCount({ count, compact = false }: { count: number; compact?: boolean }) {
  if (count <= 1) return null;

  return (
    <View
      className="flex-row items-center rounded-full bg-black/65"
      style={{
        paddingHorizontal: compact ? 6 : spacing.sm,
        paddingVertical: compact ? 1 : spacing.xs,
      }}
    >
      {!compact ? (
        <Ionicons name="images-outline" size={11} color="#FFFFFF" style={{ marginRight: 3 }} />
      ) : null}
      <Text variant="caption" className="text-white">
        {count}
      </Text>
    </View>
  );
}

export interface SaveControlProps {
  saved: boolean;
  onToggle: () => void;
  /**
   * A request is in flight for this listing.
   *
   * The control locks rather than showing a spinner. The heart is already
   * showing the optimistic result, so a spinner would replace a correct answer
   * with a question; what matters is that a second tap cannot queue a second
   * request, which is what this prevents. Dimming says "not right now" without
   * changing what the icon claims.
   */
  busy?: boolean;
}

interface SaveControlRenderProps extends SaveControlProps {
  /**
   * Drops the dark disc, for a control sitting on a card surface rather than
   * over a photograph. The disc exists to stay legible over an unknown image;
   * on a white row it would be the loudest thing in the list.
   */
  bare?: boolean;
  /** The unsaved glyph colour when `bare`. Saved is always the brand red. */
  tint?: string;
}

/**
 * The save control.
 *
 * ---------------------------------------------------------------------------
 * THE TARGET IS 44, THE GLYPH IS 20, AND THAT GAP IS THE POINT
 *
 * The outer pressable measures `touchTarget.min` square. The visible disc is
 * 34. Shrinking the target to match the disc is the single most common way a
 * clean-looking mobile interface becomes annoying to use, and it is invisible
 * in a screenshot — which is exactly why it survives review.
 *
 * The disc is offset INTO the corner by the difference, so the visible object
 * sits at the same 12pt inset as the intent badge opposite it while the target
 * runs to the card edge. Fitts's law twice over: bigger, and closer to a
 * corner the thumb can overshoot into.
 *
 * ---------------------------------------------------------------------------
 * FILLED MEANS SAVED, OUTLINE MEANS NOT, AND NOTHING ELSE MEANS EITHER
 *
 * One shape, one meaning, on every screen that shows a property — see
 * `features/saved/hooks.ts` for what the action actually does and why the
 * honesty lives in the confirmation rather than in the icon.
 */
/** The saved heart, on any surface. Not a token: it must survive being drawn
 *  over an arbitrary photograph, where a scheme-aware red would not. */
const SAVED_RED = '#FF4D4F';

export function SaveControl({
  saved,
  onToggle,
  busy = false,
  bare = false,
  tint,
}: SaveControlRenderProps) {
  const glyph = (
    <Ionicons
      name={saved ? 'heart' : 'heart-outline'}
      size={bare ? 21 : 19}
      // Brand red when set. The unset state must not be a pale red: a
      // half-tinted heart reads as a third state.
      color={saved ? SAVED_RED : bare ? (tint ?? '#8A8A8E') : '#FFFFFF'}
    />
  );

  return (
    <PressableScale
      accessibilityRole="switch"
      accessibilityLabel={saved ? 'Withdraw enquiry' : 'Enquire about this property'}
      accessibilityState={{ checked: saved, busy, disabled: busy }}
      disabled={busy}
      onPress={onToggle}
      activeScale={0.86}
      style={{
        width: touchTarget.min,
        height: touchTarget.min,
        alignItems: 'center',
        justifyContent: 'center',
        opacity: busy ? 0.5 : 1,
      }}
    >
      {bare ? (
        glyph
      ) : (
        <View
          className="items-center justify-center rounded-full bg-black/55"
          style={{ width: CONTROL_DISC, height: CONTROL_DISC }}
        >
          {glyph}
        </View>
      )}
    </PressableScale>
  );
}

export interface CompareControlProps {
  selected: boolean;
  /** False when a third pick would exceed the cap or clash with the type
   *  already anchoring the selection. Renders disabled rather than vanishing. */
  disabled: boolean;
  onToggle: () => void;
}

/**
 * Compare selection, which takes the save control's corner while compare mode
 * is on.
 *
 * It used to sit there permanently, as an unlabelled empty circle over every
 * photo in the feed — a control whose meaning nobody could guess, occupying the
 * one corner where every user on earth looks for the save control. It is now
 * behind the toolbar's Compare toggle: common path on the surface, rare path
 * one deliberate step deeper.
 */
export function CompareControl({ selected, disabled, onToggle }: CompareControlProps) {
  const theme = useTheme();

  return (
    <PressableScale
      accessibilityRole="checkbox"
      accessibilityState={{ checked: selected, disabled }}
      accessibilityLabel={selected ? 'Remove from comparison' : 'Add to comparison'}
      disabled={disabled && !selected}
      onPress={onToggle}
      activeScale={0.86}
      style={{
        width: touchTarget.min,
        height: touchTarget.min,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <View
        className="items-center justify-center rounded-full bg-black/55"
        style={{ width: CONTROL_DISC, height: CONTROL_DISC }}
      >
        <Ionicons
          name={selected ? 'checkmark-circle' : 'ellipse-outline'}
          size={21}
          color={
            selected ? theme.colors.accent : disabled ? 'rgba(255,255,255,0.4)' : '#FFFFFF'
          }
        />
      </View>
    </PressableScale>
  );
}

/**
 * The photo, or an honest placeholder for the listings that have none.
 *
 * Clipped by the card's own `overflow: hidden`, so it inherits the card radius
 * on the corners it touches and stays square on the ones it does not. That is
 * what keeps the feed card and the list row concentric without either of them
 * hard-coding the other's radius.
 */
export function Cover({
  uri,
  aspectRatio,
  width,
  iconSize = 26,
}: {
  uri?: string;
  aspectRatio: number;
  width?: number | `${number}%`;
  iconSize?: number;
}) {
  const theme = useTheme();
  const style = { width: width ?? '100%', aspectRatio } as const;

  if (uri) return <Image uri={uri} size="thumb" style={style} />;

  return (
    <View className="items-center justify-center bg-surface-muted" style={style}>
      <Ionicons name="image-outline" size={iconSize} color={theme.colors.textMuted} />
    </View>
  );
}

/**
 * The fact row: configuration, area, type — each an icon and a value.
 *
 * The dot-joined string it replaced ("3 BHK · 1,250 sqft · Apartment") is one
 * run of small grey text, so the reader parses left to right to find the field
 * they care about and at a glance it reads as a single texture rather than as
 * three facts. The icon is what lets the eye jump straight to the area figure
 * without reading the two values before it.
 *
 * `flexShrink` on every cell rather than fixed widths: the type name runs from
 * "Villa" to "Independent House / Villa" and the row absorbs that instead of
 * pushing the area figure off the card.
 */
export interface Spec {
  icon: keyof typeof Ionicons.glyphMap;
  value: string;
}

export function specs(property: PropertySummary): Spec[] {
  const items: Spec[] = [];

  // `bhk` arrives pre-suffixed on real data ("2 BHK", "5+ BHK"), so the suffix
  // is added only when genuinely missing.
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

  // The denormalised string, never the populated `propertyType` ref: the ref is
  // null or wrong on every live listing.
  const type = property.propertyTypeName ?? property.subcategoryName ?? property.categoryName;
  if (type) items.push({ icon: 'home-outline', value: type });

  return items;
}

export function SpecRow({ items, compact = false }: { items: Spec[]; compact?: boolean }) {
  const theme = useTheme();
  if (items.length === 0) return null;

  return (
    <View className="flex-row items-center" style={{ gap: compact ? spacing.md : spacing.base }}>
      {items.map((item) => (
        <View key={item.icon} className="flex-row items-center" style={{ flexShrink: 1 }}>
          <Ionicons name={item.icon} size={compact ? 13 : 15} color={theme.colors.textMuted} />
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

/**
 * Card geometry, in one place so the three cards and the skeleton agree.
 *
 * Radius is a function of surface size, not taste: a full-width photo card
 * takes `xl`, a 96pt-tall row takes `lg`. Padding is `base` on both, which
 * makes the inner content box concentric with each outer radius.
 */
export const CARD_RADIUS = radius.xl;
export const ROW_RADIUS = radius.lg;

/** One shadow definition. A card carries a shadow OR a border, never both. */
export const cardShadow = {
  shadowColor: '#000',
  shadowOpacity: 0.06,
  shadowRadius: 10,
  shadowOffset: { width: 0, height: 3 },
  elevation: 2,
} as const;
