import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { View, type LayoutChangeEvent } from 'react-native';
import {
  runOnJS,
  useAnimatedReaction,
  useAnimatedScrollHandler,
  useSharedValue,
  type SharedValue,
} from 'react-native-reanimated';

/**
 * Deferred mounting for sections below the fold.
 *
 * This is a rate-limit mechanism before it is a performance one, and that is
 * worth stating plainly because it looks like a lazy-render optimisation.
 *
 * `/api/properties/search` is capped at 20 requests per minute PER IP
 * (backend/server.js `searchLimiter`), and on Indian mobile networks that IP is
 * a carrier NAT gateway shared by a large number of strangers. A Home screen
 * built from ten curated collections fires ten searches the instant it mounts.
 * That alone is half the budget, it is spent before the user has scrolled far
 * enough to see eight of the ten results, and whatever they do next — open the
 * browse screen, type a search — lands on a 429. The screen would feel fast for
 * two seconds and then break, which is worse than being slow.
 *
 * So a section does not fetch because it exists. It fetches because it is about
 * to be seen. Mounting is what triggers the query (the hook lives inside the
 * child), so withholding the mount withholds the request. In practice the first
 * paint costs two or three searches instead of ten, and the rest arrive spread
 * across the user's own scrolling, which is naturally slower than the limiter.
 *
 * A section reveals when it comes within `margin` points of the viewport, not
 * when it enters it, so the request is already in flight by the time the row
 * would appear. `REVEAL_MARGIN` is roughly one screen height: near enough that
 * the budget is not spent up front, far enough that the data has landed before
 * the user gets there.
 *
 * Revealing LATCHES. A section that has been seen stays mounted, so scrolling
 * back up costs nothing and never refires a query.
 *
 * ---------------------------------------------------------------------------
 * Why the scroll position is a shared value and not React state.
 *
 * The obvious version puts the offset in `useState` via `onScroll`. That
 * re-renders the entire Home tree on every scroll frame, which for a screen of
 * ten image rails is exactly the jank this redesign is meant to remove.
 *
 * Instead the offset lives on the UI thread and each `Reveal` watches it with
 * `useAnimatedReaction`. Nothing re-renders while scrolling. When one section
 * crosses its threshold, that ONE section hops to the JS thread and re-renders
 * itself, once, permanently. Scrolling the whole screen costs a handful of
 * single-component renders in total.
 */

/** How far ahead of the viewport a section starts loading, in points. */
const REVEAL_MARGIN = 700;

interface ScrollRevealValue {
  offset: SharedValue<number>;
  viewport: SharedValue<number>;
}

const ScrollRevealContext = createContext<ScrollRevealValue | null>(null);

/**
 * Supplies a reveal host to a scroll view a screen builds itself.
 *
 * `RevealScrollView` covers the common case. This exists for the screen that
 * also needs the scroll offset for its own chrome — Home drives a sticky
 * header from it — because that header renders OUTSIDE the scroll view and so
 * cannot read the context from within it. Composing here means there is still
 * exactly one scroll listener on the UI thread rather than a second one added
 * alongside.
 */
export function ScrollRevealProvider({
  value,
  children,
}: {
  value: ScrollRevealValue;
  children: React.ReactNode;
}) {
  return <ScrollRevealContext.Provider value={value}>{children}</ScrollRevealContext.Provider>;
}

/**
 * Wraps the scrolling surface.
 *
 * Put the returned handler and layout callback on an `Animated.ScrollView` and
 * the context on a `ScrollRevealProvider` around it. Five lines, and it hands
 * the screen the scroll offset — which Home needs for its sticky header, and
 * which a wrapper component could only have hidden.
 *
 * There WAS a `RevealScrollView` that did this in one component. It was
 * deleted on 2026-08-24 when Home, its only consumer, outgrew it: the header
 * renders outside the scroll view and so cannot read the context from within
 * it. It is in git history if a screen ever wants the simple path back.
 */
export function useScrollRevealHost() {
  const offset = useSharedValue(0);
  const viewport = useSharedValue(0);

  const onScroll = useAnimatedScrollHandler((event) => {
    offset.value = event.contentOffset.y;
  });

  const onLayout = useCallback(
    (event: LayoutChangeEvent) => {
      viewport.value = event.nativeEvent.layout.height;
    },
    [viewport]
  );

  const context = useMemo<ScrollRevealValue>(() => ({ offset, viewport }), [offset, viewport]);

  return { context, onScroll, onLayout };
}

export type { ScrollRevealValue };

export interface RevealProps {
  children: React.ReactNode;
  /**
   * Rendered until the section is revealed. Give it roughly the height of the
   * real content: a zero-height placeholder means every section below shifts
   * upward as this one loads, and the scroll position the user is holding
   * drifts under their thumb.
   */
  placeholder?: React.ReactNode;
  /** Points of lead time before the viewport. */
  margin?: number;
}

/**
 * Mounts its children once the section approaches the viewport, then keeps them
 * mounted.
 *
 * Outside a `RevealScrollView` this renders immediately. That default is
 * deliberate: a section that silently never loads because someone moved it to a
 * different screen is a far worse failure than one extra request.
 */
export function Reveal({ children, placeholder = null, margin = REVEAL_MARGIN }: RevealProps) {
  const host = useContext(ScrollRevealContext);
  const [revealed, setRevealed] = useState(host === null);
  const top = useSharedValue(Number.POSITIVE_INFINITY);

  const reveal = useCallback(() => setRevealed(true), []);

  /**
   * Measurement and a first check, together.
   *
   * The check has to happen here as well as in the reaction below, because the
   * reaction only fires when the offset CHANGES. A section that is already on
   * screen at mount — or a Home short enough that it never scrolls at all —
   * would otherwise wait for a scroll event that never comes.
   */
  const onLayout = useCallback(
    (event: LayoutChangeEvent) => {
      const y = event.nativeEvent.layout.y;
      top.value = y;

      if (!host || revealed) return;
      if (host.offset.value + host.viewport.value + margin >= y) reveal();
    },
    [host, revealed, margin, top, reveal]
  );

  useAnimatedReaction(
    () => {
      if (!host) return false;
      return host.offset.value + host.viewport.value + margin >= top.value;
    },
    (isNear, wasNear) => {
      // Guarded on the transition rather than the value, so this crosses to the
      // JS thread exactly once per section for the lifetime of the screen.
      if (isNear && !wasNear) runOnJS(reveal)();
    },
    [host, margin]
  );

  return (
    <View onLayout={onLayout}>{revealed ? children : placeholder}</View>
  );
}
