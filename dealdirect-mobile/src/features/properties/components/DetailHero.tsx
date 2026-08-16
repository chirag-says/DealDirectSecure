import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useRef, useState } from 'react';
import {
  FlatList,
  Pressable,
  useWindowDimensions,
  View,
  type NativeScrollEvent,
  type NativeSyntheticEvent,
} from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  type SharedValue,
} from 'react-native-reanimated';

import { gesture, spacing, useTheme } from '@/theme';
import { Image, PressableScale, Scrim, Text } from '@/ui';
import type { GalleryImage } from '../types';

/**
 * The photo carousel at the top of a listing.
 *
 * Full-bleed and running under the status bar, so the screen that hosts it must
 * not reserve a top inset.
 *
 * Chrome is dark-translucent rather than surface-coloured. A pale control
 * disappears against a bright sky and a dark one disappears against a shadowed
 * wall, so neither scheme's surface colour is legible over an arbitrary
 * photograph. Dark with white content works over every image, which is the only
 * requirement here.
 *
 * The `hero` scrim darkens the top as well as the bottom, which keeps the nav
 * controls legible over a bright sky where the card variant holds near-zero for
 * its whole upper half.
 *
 * ---------------------------------------------------------------------------
 * THE HEIGHT IS DERIVED FROM THE WIDTH — changed 2026-08-15
 *
 * It was a flat 320. A fixed height means a fixed CROP, and a fixed crop over a
 * variable width is a different photograph per device: 320 is 85% of a 375pt
 * screen's width and 74% of a 430pt one, so the same listing showed more sky on
 * the larger phone. Deriving it keeps the framing identical everywhere and the
 * clamp stops a tablet-width device from handing the photo two thirds of the
 * page.
 *
 * ---------------------------------------------------------------------------
 * TWO INDICATORS, AND THEY SAY DIFFERENT THINGS
 *
 * The old version had one weak chip reading "1 / 6" tucked into the bottom-right
 * corner, where the content sheet's rounded top clipped it. It was doing two
 * jobs badly: saying where you are, and being the tap target for the full
 * gallery.
 *
 * They are separated now, and neither is a second copy of the other:
 *
 *   dots (bottom-centre)   WHERE you are. The universal swipe signifier, and
 *                          the thing that says another photo exists at all.
 *                          Shown only up to `MAX_DOTS`.
 *   button (bottom-right)  HOW MANY there are, and the way into the viewer.
 *                          An action, not a pagination system.
 *
 * Past `MAX_DOTS` the dots stop being countable and start being texture, so
 * they are dropped and the button takes the position back as "3 / 24". One
 * system on screen at any count — never both saying the same thing.
 *
 * A next-image PEEK was considered and rejected. It requires horizontal
 * gutters, and gutters end the full-bleed treatment that makes this hero read
 * as a photograph rather than as a card; on a 375pt screen the peek would also
 * be about 16pt, which is not enough to be legible as an image and is plenty to
 * make the layout look accidentally misaligned.
 *
 * ---------------------------------------------------------------------------
 * PARALLAX AND STRETCH
 *
 * `scrollY` is the host scroll view's offset, shared from the UI thread. Two
 * behaviours come off it, and both are the physical reading of the same fact:
 * the photo sits BEHIND the content rather than being the first item in it.
 *
 *   scrolling up   the photo drifts at a fraction of the content's speed, so
 *                  the sheet of content reads as sliding over it
 *   pulling down   the photo is pinned to the top edge and scales from its top
 *                  origin, so it grows into the slack instead of leaving a band
 *                  of background above it
 *
 * The content block below is opaque and paints after this one, so the grown
 * photo passes underneath it and needs no clipping container. A container with
 * `overflow: hidden` would clip away the stretch that is the whole point.
 *
 * Under reduced motion both are dropped. Parallax is textbook vestibular
 * motion, and unlike a press there is nothing here that needs acknowledging —
 * the scroll itself is the feedback.
 *
 * ---------------------------------------------------------------------------
 * WHY A PAGED FlatList AND NOT A MAPPED ScrollView
 *
 * Listings carry up to 65 images (15 flat plus 50 categorised). A ScrollView
 * mounts every child immediately, so opening a well-photographed listing would
 * decode sixty-odd full-width images before the first paint. The FlatList
 * renders a window of three and recycles, which is the difference between a
 * carousel that opens instantly and one that stutters for a second first.
 *
 * Page position is read from `onMomentumScrollEnd` rather than from
 * `onViewableItemsChanged`. The viewability callback fires mid-swipe against a
 * configurable threshold and produces a counter that flickers to the next
 * number before the page has settled; momentum end fires once, after the page
 * has landed, which is exactly when the counter should change.
 */

/**
 * The hero's height for a given screen width.
 *
 * A function rather than a constant because it depends on the device — see the
 * note above. `DetailHeader` needs it to know where the photo ends and the
 * collapsed bar begins, and the detail screen's skeleton needs it to match.
 */
export function heroHeight(width: number): number {
  return Math.round(Math.min(Math.max(width * 0.86, 300), 420));
}

/** Above this, dots stop being countable and become texture. */
const MAX_DOTS = 8;

/** How much slower than the content the photo travels. 0 pins it, 1 is none. */
const PARALLAX_FACTOR = 0.4;

export interface DetailHeroProps {
  images: GalleryImage[];
  /** Fallback for listings whose only image never reached the gallery list. */
  fallbackUri?: string;
  /** Opens the full-screen viewer at the photo currently on screen. */
  onOpenGallery?: (index: number) => void;
  /** Host scroll offset. Drives the parallax and the overscroll stretch. */
  scrollY?: SharedValue<number>;
}

export function DetailHero({ images, fallbackUri, onOpenGallery, scrollY }: DetailHeroProps) {
  const { width } = useWindowDimensions();
  const theme = useTheme();
  const [index, setIndex] = useState(0);
  const reduceMotion = useReducedMotion();

  const height = heroHeight(width);

  // Read in the scroll handler, which must not re-subscribe on every page
  // change, so it is held in a ref rather than in the closure.
  const widthRef = useRef(width);
  widthRef.current = width;

  const items: GalleryImage[] =
    images.length > 0 ? images : fallbackUri ? [{ uri: fallbackUri }] : [];

  const handleMomentumEnd = useCallback((event: NativeSyntheticEvent<NativeScrollEvent>) => {
    setIndex(Math.round(event.nativeEvent.contentOffset.x / widthRef.current));
  }, []);

  const handlePress = useCallback(() => onOpenGallery?.(index), [onOpenGallery, index]);

  const parallaxStyle = useAnimatedStyle(() => {
    const y = scrollY?.value ?? 0;

    if (reduceMotion) {
      return { transform: [{ translateY: 0 }, { scale: 1 }] };
    }

    // Pulled down. Cancel the content's own displacement so the top edge stays
    // welded to the screen edge, then grow downward from that origin.
    if (y < 0) {
      return { transform: [{ translateY: y }, { scale: 1 + -y / height }] };
    }

    return { transform: [{ translateY: y * PARALLAX_FACTOR }, { scale: 1 }] };
  }, [reduceMotion, height]);

  const multiple = items.length > 1;
  const showDots = multiple && items.length <= MAX_DOTS;

  return (
    <Animated.View style={[{ height, transformOrigin: 'top' }, parallaxStyle]}>
      {items.length > 0 ? (
        <FlatList
          data={items}
          horizontal
          pagingEnabled
          showsHorizontalScrollIndicator={false}
          keyExtractor={(item, i) => `${item.uri}-${i}`}
          onMomentumScrollEnd={handleMomentumEnd}
          // Current, plus one either side. Exactly the working set §25 asks
          // for: the neighbours are decoded before they are swiped to, and
          // nothing beyond them is held.
          initialNumToRender={1}
          windowSize={3}
          removeClippedSubviews
          // Every page is exactly the screen width, so the list never has to
          // measure to know where a page starts. Without this a jump to a deep
          // index scrolls through everything in between.
          getItemLayout={(_, i) => ({ length: width, offset: width * i, index: i })}
          renderItem={({ item }) => (
            <Pressable
              accessibilityRole="imagebutton"
              accessibilityLabel={
                item.label ? `${item.label} photo, open full screen` : 'Open photo full screen'
              }
              onPress={handlePress}
              disabled={!onOpenGallery}
            >
              <Image uri={item.uri} size="medium" style={{ width, height }} />
            </Pressable>
          )}
        />
      ) : (
        <View
          className="items-center justify-center bg-surface-muted"
          style={{ width: '100%', height }}
        >
          <Ionicons name="image-outline" size={32} color={theme.colors.textMuted} />
          <Text variant="footnote" tone="muted" className="mt-sm">
            No photo
          </Text>
        </View>
      )}

      <Scrim variant="hero" />

      {/*
        Everything below sits `BOTTOM_INSET` up from the photo's edge rather
        than at it. The content sheet's rounded top corner overlaps the last
        ~20pt of the photo, and the old counter chip was drawn inside that
        overlap — visibly clipped on a real device.
      */}
      {items[index]?.label ? (
        <View
          className="absolute rounded-full bg-black/55 px-md py-xs"
          style={{ left: spacing.lg, bottom: BOTTOM_INSET }}
        >
          <Text variant="caption" className="text-white">
            {items[index].label}
          </Text>
        </View>
      ) : null}

      {showDots ? <Dots count={items.length} index={index} /> : null}

      {multiple ? (
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={`View all ${items.length} photos`}
          onPress={handlePress}
          disabled={!onOpenGallery}
          hitSlop={gesture.hitSlop}
          activeScale={0.94}
          style={{
            position: 'absolute',
            right: spacing.lg,
            bottom: BOTTOM_INSET,
            flexDirection: 'row',
            alignItems: 'center',
            // 0.72 rather than 0.55: this is the one control on the photo that
            // has to be readable at a glance over any image, and the old chip
            // was reported as too easy to miss.
            backgroundColor: 'rgba(0,0,0,0.72)',
            borderRadius: 999,
            paddingHorizontal: spacing.md,
            minHeight: 32,
          }}
        >
          <Ionicons name="images" size={14} color="#FFFFFF" />
          <Text variant="footnote" className="ml-xs text-white" style={{ fontWeight: '600' }}>
            {/* With dots on screen the button states the TOTAL, so the two are
                not two copies of the same fact. Without them it takes the
                position back. */}
            {showDots ? `${items.length} photos` : `${index + 1} / ${items.length}`}
          </Text>
        </PressableScale>
      ) : null}
    </Animated.View>
  );
}

/**
 * Clear of the content sheet's rounded top corner, which overlaps the photo by
 * 20pt. `lg` on top of that leaves the chrome sitting on the photograph rather
 * than on the seam.
 */
const BOTTOM_INSET = 20 + spacing.lg;

/**
 * Position, and nothing else.
 *
 * The active dot is wider rather than only brighter — state carried by shape as
 * well as by colour survives both a bright photograph washing out the contrast
 * and a user who cannot distinguish the two tones.
 *
 * `pointerEvents="none"`: a drag that starts on the dots must still reach the
 * photo underneath. They are decorative here; the accessible position is
 * announced by the button beside them, which is a real control.
 */
function Dots({ count, index }: { count: number; index: number }) {
  return (
    <View
      pointerEvents="none"
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      // Same bottom and same height as the button beside them, so the two sit
      // on one baseline instead of at two arbitrary offsets.
      className="absolute w-full flex-row items-center justify-center"
      style={{ bottom: BOTTOM_INSET, height: 32, gap: 5 }}
    >
      {Array.from({ length: count }, (_, i) => (
        <View
          key={i}
          style={{
            height: 5,
            width: i === index ? 16 : 5,
            borderRadius: 999,
            backgroundColor: i === index ? '#FFFFFF' : 'rgba(255,255,255,0.5)',
          }}
        />
      ))}
    </View>
  );
}
