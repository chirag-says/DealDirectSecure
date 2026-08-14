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

import { useTheme } from '@/theme';
import { Image, Scrim, Text } from '@/ui';
import type { GalleryImage } from '../types';

/**
 * The photo carousel at the top of a listing.
 *
 * Full-bleed and running under the status bar, so the screen that hosts it
 * must not reserve a top inset.
 *
 * Chrome is dark-translucent rather than surface-coloured. A pale control
 * disappears against a bright sky and a dark one disappears against a shadowed
 * wall, so neither scheme's surface colour is legible over an arbitrary
 * photograph. Dark with white content works over every image, which is the
 * only requirement here. Same reasoning as the intent chip on `PropertyCard`.
 *
 * The `hero` scrim is the right variant rather than the card default: it
 * darkens the top as well as the bottom, which keeps the nav controls legible
 * over a bright sky, where the card variant holds near-zero for its whole
 * upper half.
 *
 * ---------------------------------------------------------------------------
 * THE BACK BUTTON IS NOT HERE ANY MORE
 *
 * It used to be, floated over the photo, and it went off the top of the screen
 * with the photo. On a listing with four attribute sections and an EMI
 * calculator that is several thousand pixels with no way back, which is the
 * one control a detail screen may never lose. It now belongs to
 * `DetailHeader`, which stays put and changes appearance as the photo leaves.
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
 *                  origin, so it grows into the slack instead of leaving a
 *                  band of background above it
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
 * number before the page has actually settled; momentum end fires once, after
 * the page has landed, which is exactly when the counter should change.
 */

export const HERO_HEIGHT = 320;

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

  // Read in the scroll handler, which must not re-subscribe on every page
  // change, so it is held in a ref rather than in the closure.
  const widthRef = useRef(width);
  widthRef.current = width;

  const items: GalleryImage[] =
    images.length > 0 ? images : fallbackUri ? [{ uri: fallbackUri }] : [];

  const handleMomentumEnd = useCallback((event: NativeSyntheticEvent<NativeScrollEvent>) => {
    const page = Math.round(event.nativeEvent.contentOffset.x / widthRef.current);
    setIndex(page);
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
      return {
        transform: [{ translateY: y }, { scale: 1 + -y / HERO_HEIGHT }],
      };
    }

    return { transform: [{ translateY: y * PARALLAX_FACTOR }, { scale: 1 }] };
  }, [reduceMotion]);

  return (
    <Animated.View
      style={[{ height: HERO_HEIGHT, transformOrigin: 'top' }, parallaxStyle]}
    >
      {items.length > 0 ? (
        <FlatList
          data={items}
          horizontal
          pagingEnabled
          showsHorizontalScrollIndicator={false}
          keyExtractor={(item, i) => `${item.uri}-${i}`}
          onMomentumScrollEnd={handleMomentumEnd}
          initialNumToRender={1}
          windowSize={3}
          removeClippedSubviews
          // Every page is exactly the screen width, so the list never has to
          // measure to know where a page starts. Without this a jump to a
          // deep index scrolls through everything in between.
          getItemLayout={(_, i) => ({ length: width, offset: width * i, index: i })}
          renderItem={({ item }) => (
            <Pressable
              accessibilityRole="imagebutton"
              accessibilityLabel={item.label ? `${item.label} photo` : 'Property photo'}
              onPress={handlePress}
              disabled={!onOpenGallery}
            >
              <Image
                uri={item.uri}
                size="medium"
                style={{ width, height: HERO_HEIGHT }}
              />
            </Pressable>
          )}
        />
      ) : (
        <View
          className="items-center justify-center bg-surface-muted"
          style={{ width: '100%', height: HERO_HEIGHT }}
        >
          <Ionicons name="image-outline" size={32} color={theme.colors.textMuted} />
          <Text variant="footnote" tone="muted" className="mt-sm">
            No photo
          </Text>
        </View>
      )}

      <Scrim variant="hero" />

      {/*
        The room this photo shows, when it came from a categorised bucket.
        Absent for the flat `images[]` array, which carries no room, so the
        label does not reserve space it cannot always fill.
      */}
      {items[index]?.label ? (
        <View className="absolute bottom-base left-lg rounded-full bg-black/55 px-md py-xs">
          <Text variant="caption" className="text-white">
            {items[index].label}
          </Text>
        </View>
      ) : null}

      {items.length > 1 ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`View all ${items.length} photos`}
          onPress={handlePress}
          disabled={!onOpenGallery}
          hitSlop={12}
          className="absolute bottom-base right-lg flex-row items-center rounded-full bg-black/55 px-md py-xs"
        >
          <Ionicons name="images-outline" size={13} color="#ffffff" />
          <Text variant="caption" className="ml-xs text-white">
            {index + 1} / {items.length}
          </Text>
        </Pressable>
      ) : null}
    </Animated.View>
  );
}
