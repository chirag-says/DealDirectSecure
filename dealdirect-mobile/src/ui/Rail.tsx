import React, { useCallback, useMemo, useRef } from 'react';
import {
  FlatList,
  useWindowDimensions,
  type ListRenderItemInfo,
  type NativeScrollEvent,
  type NativeSyntheticEvent,
} from 'react-native';

import { spacing } from '@/theme';

/**
 * The horizontal scroller every discovery row on Home is built from.
 *
 * There is exactly one of these because there were nearly nine of them. Home
 * has a rail of properties, of collections, of builders, of projects, of
 * localities, of budgets. Written per section they drift within a week: one
 * gets snapping and another does not, the gutters disagree by 4px, the third
 * forgets `showsHorizontalScrollIndicator` and grows a scrollbar nothing else
 * has. The eye reads that as an assembled page, which is the specific failure
 * this redesign exists to fix.
 *
 * Three things are decided here and nowhere else.
 *
 * **The peek.** Card widths are a fraction of the viewport, never a round
 * number, so the next card is always partly visible at the right edge. That
 * sliver is the entire affordance for horizontal scrolling — it is what says
 * "there is more" without a chevron, an arrow or a hint animation. A card width
 * that happens to divide the screen evenly produces a row that looks complete
 * and stops being scrolled.
 *
 * **The snap.** `snapToInterval` is the card pitch (width plus gap), so a flick
 * always settles with a card aligned to the left gutter rather than halfway
 * through one. `decelerationRate="fast"` keeps a throw from coasting past three
 * cards, which on a rail of eight loses the user their place.
 *
 * **The gutter.** Padding lives on the content container, never on the list, so
 * the row scrolls edge to edge under the screen margin instead of being clipped
 * inside it. That difference is most of why a native rail looks native.
 *
 * **The shadow room.** A scroll view clips to its own bounds, and the cards
 * carry a shadow that reaches past theirs. With no vertical padding the shadow
 * was cut flat at the card's top and bottom edge, which read as the card
 * itself being cropped (reported 2026-09-06). The content container now pads
 * vertically by the shadow's reach and the list pulls itself in by the same
 * amount, so the layout is the height it always was and the shadow has
 * somewhere to fall.
 */

/**
 * How far a rail card's shadow extends past its box, in points. Matched to
 * the cards' `shadowRadius: 12` with a 4pt downward offset; Android's
 * `elevation: 3` reaches less than this.
 */
const SHADOW_REACH = 16;

/**
 * The image box of a photographic rail card, 4:3 of the card's width.
 *
 * A fixed height used to sit here (180pt for properties, 150pt for projects)
 * against a width that is a fraction of the screen, which made the box
 * roughly 1.56:1 on a common phone. Listing photos are mostly 4:3, so cover
 * fitting cut about 15% of every one, top and bottom, and posters lost their
 * text (reported 2026-09-06). Deriving the height from the width keeps the
 * box at the photographs' own ratio, so a typical photo is shown whole.
 */
export function railImageHeight(width: number): number {
  return Math.round((width * 3) / 4);
}

/**
 * Card widths, as viewport fractions rather than fixed points.
 *
 * Fractions because the peek has to survive a 360pt Android phone and a 430pt
 * Pro Max: a fixed 300pt card peeks correctly on one and fills the screen on
 * the other. The two smallest sizes ARE fixed, because a builder logo and a
 * category icon have an intrinsic size that should not grow with the display.
 */
const RAIL_SIZES = {
  /** One dominant card, e.g. Today's Pick. Nearly full width, small peek. */
  feature: { fraction: 0.86, min: 280, max: 460 },
  /** Property cards. The default for anything photographic. */
  large: { fraction: 0.78, min: 260, max: 400 },
  /** Projects and collections: image-led but two-up on a wide screen. */
  medium: { fraction: 0.62, min: 210, max: 320 },
  /** Localities and budget bands. */
  compact: { fraction: 0.44, min: 150, max: 230 },
  /** Builder cards. Fixed: a logo has an intrinsic size. */
  small: { fixed: 148 },
  /** Category icons. Fixed, for the same reason. */
  tile: { fixed: 84 },
} as const;

export type RailSize = keyof typeof RAIL_SIZES;

/**
 * Resolve a size token to a pixel width for the current viewport.
 *
 * Exported because a card has to know its own width to lay out its image, and
 * that number must come from the same place the snap interval does. Two
 * independent guesses at "how wide is a large card" is how a rail ends up
 * snapping 6px off centre.
 */
export function useRailItemWidth(size: RailSize): number {
  const { width } = useWindowDimensions();

  return useMemo(() => {
    const spec = RAIL_SIZES[size];
    if ('fixed' in spec) return spec.fixed;

    // Clamped at both ends: the fraction is right for phones, but on a tablet
    // an unbounded 78% card is a single absurd billboard, and on a very narrow
    // display it collapses below the point where the content fits.
    return Math.min(spec.max, Math.max(spec.min, Math.round(width * spec.fraction)));
  }, [size, width]);
}

export interface RailProps<T> {
  data: readonly T[];
  size: RailSize;
  keyExtractor: (item: T, index: number) => string;
  renderItem: (item: T, width: number, index: number) => React.ReactElement | null;
  /** Gap between cards. Defaults to the `md` step. */
  gap?: number;
  accessibilityLabel?: string;
  /**
   * Fires with the nearest card index as the row is scrolled.
   *
   * Reported from `onScroll` (throttled to the frame) and only when the index
   * actually changes, so a page indicator moves the moment a card crosses the
   * halfway point, the way a native page control does. It used to report only
   * on `momentumScrollEnd`, which meant the dot moved only after the snap had
   * fully settled, half a second or more after the finger lifted; and on
   * Android a drag released at a snap point can end without a momentum event
   * at all, leaving the dot on the wrong card (reported 2026-09-06). Momentum
   * end is still handled, as a final correction, and is a no-op when the
   * scroll pass already reported the settled index.
   *
   * A callback rather than internal state because the indicator is drawn by
   * the section around the rail, not inside it, and a rail with no indicator
   * pays nothing: neither handler is attached without one.
   */
  onIndexChange?: (index: number) => void;
}

export function Rail<T>({
  data,
  size,
  keyExtractor,
  renderItem,
  gap = spacing.md,
  accessibilityLabel,
  onIndexChange,
}: RailProps<T>) {
  const itemWidth = useRailItemWidth(size);
  const pitch = itemWidth + gap;

  // The last index reported, so a scroll frame that lands on the same card
  // costs nothing: no state update in the section, no re-render of the row.
  const reported = useRef(0);

  const report = useCallback(
    (event: NativeSyntheticEvent<NativeScrollEvent>) => {
      if (!onIndexChange) return;
      const raw = Math.round(event.nativeEvent.contentOffset.x / pitch);
      const index = Math.max(0, Math.min(data.length - 1, raw));
      if (index === reported.current) return;
      reported.current = index;
      onIndexChange(index);
    },
    [onIndexChange, pitch, data.length]
  );

  const render = useCallback(
    ({ item, index }: ListRenderItemInfo<T>) => renderItem(item, itemWidth, index),
    [renderItem, itemWidth]
  );

  /**
   * Every card in a rail is the same width, so the list never has to measure
   * one. Without this, a horizontal FlatList lays out the first screenful,
   * measures, then corrects, and the row visibly settles on mount.
   */
  const getItemLayout = useCallback(
    (_: ArrayLike<T> | null | undefined, index: number) => ({
      length: pitch,
      offset: pitch * index,
      index,
    }),
    [pitch]
  );

  return (
    <FlatList
      horizontal
      data={data as T[]}
      renderItem={render}
      keyExtractor={keyExtractor}
      getItemLayout={getItemLayout}
      showsHorizontalScrollIndicator={false}
      // Snap to the card pitch, and align to the leading edge so the card that
      // settles sits exactly on the screen gutter.
      snapToInterval={pitch}
      snapToAlignment="start"
      decelerationRate="fast"
      onScroll={onIndexChange ? report : undefined}
      onMomentumScrollEnd={onIndexChange ? report : undefined}
      scrollEventThrottle={16}
      // Pulled in by the shadow room the content container adds below, so the
      // rail occupies the same height it did without it.
      style={{ marginVertical: -SHADOW_REACH }}
      // On the content container, not the list: the row must scroll UNDER the
      // screen margin rather than being clipped inside it. The vertical padding
      // is the shadow room; see the module doc.
      contentContainerStyle={{
        paddingHorizontal: spacing.base,
        paddingVertical: SHADOW_REACH,
        gap,
      }}
      accessibilityLabel={accessibilityLabel}
      // Rails hold eight to twelve items, all of which are cheap once their
      // image is cached. Windowing them costs more in blank cells during a
      // flick than it saves in memory.
      initialNumToRender={4}
      windowSize={5}
      removeClippedSubviews={false}
    />
  );
}
