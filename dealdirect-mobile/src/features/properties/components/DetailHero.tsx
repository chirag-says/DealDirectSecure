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
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Image, Scrim, Text } from '@/ui';
import type { GalleryImage } from '../types';

/**
 * The photo carousel at the top of a listing.
 *
 * Full-bleed and running under the status bar, so the screen that hosts it
 * must not reserve a top inset. That is why this owns its own inset for the
 * back button rather than letting `Screen` handle it: the chrome needs to
 * clear the notch, the photograph does not.
 *
 * Chrome is dark-translucent rather than surface-coloured. A pale control
 * disappears against a bright sky and a dark one disappears against a shadowed
 * wall, so neither scheme's surface colour is legible over an arbitrary
 * photograph. Dark with white content works over every image, which is the
 * only requirement here. Same reasoning as the intent chip on `PropertyCard`.
 *
 * The `hero` scrim is the right variant rather than the card default: it
 * darkens the top as well as the bottom, which keeps the back button legible
 * over a bright sky, where the card variant holds near-zero for its whole
 * upper half.
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

export interface DetailHeroProps {
  images: GalleryImage[];
  /** Fallback for listings whose only image never reached the gallery list. */
  fallbackUri?: string;
  onBack: () => void;
  /** Opens the full-screen viewer at the photo currently on screen. */
  onOpenGallery?: (index: number) => void;
}

export function DetailHero({ images, fallbackUri, onBack, onOpenGallery }: DetailHeroProps) {
  const insets = useSafeAreaInsets();
  const { width } = useWindowDimensions();
  const [index, setIndex] = useState(0);

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

  const current = items[index];

  return (
    <View style={{ height: HERO_HEIGHT }}>
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
          <Ionicons name="image-outline" size={32} color="#94a3b8" />
          <Text variant="footnote" tone="muted" className="mt-sm">
            No photo
          </Text>
        </View>
      )}

      <Scrim variant="hero" />

      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Go back"
        onPress={onBack}
        hitSlop={12}
        className="absolute left-md h-11 w-11 items-center justify-center rounded-full bg-black/55"
        style={{ top: insets.top + 8 }}
      >
        <Ionicons name="chevron-back" size={22} color="#ffffff" />
      </Pressable>

      {/*
        The room this photo shows, when it came from a categorised bucket.
        Absent for the flat `images[]` array, which carries no room, so the
        label does not reserve space it cannot always fill.
      */}
      {current?.label ? (
        <View className="absolute bottom-md left-md rounded-full bg-black/65 px-sm py-xs">
          <Text variant="caption" className="text-white">
            {current.label}
          </Text>
        </View>
      ) : null}

      {items.length > 1 ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`View all ${items.length} photos`}
          onPress={handlePress}
          disabled={!onOpenGallery}
          hitSlop={8}
          className="absolute bottom-md right-md flex-row items-center rounded-full bg-black/65 px-sm py-xs"
        >
          <Ionicons name="images-outline" size={13} color="#ffffff" />
          <Text variant="caption" className="ml-xs text-white">
            {index + 1} / {items.length}
          </Text>
        </Pressable>
      ) : null}
    </View>
  );
}
