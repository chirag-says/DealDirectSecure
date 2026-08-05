import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  FlatList,
  Pressable,
  useWindowDimensions,
  View,
  type NativeScrollEvent,
  type NativeSyntheticEvent,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { usePropertyDetail, ZoomableImage } from '@/features/properties';
import { EmptyState, Screen, Text } from '@/ui';

/**
 * Full-screen photo viewer.
 *
 * ---------------------------------------------------------------------------
 * THIS SCREEN COSTS NO EXTRA REQUEST AND NO EXTRA VIEW COUNT
 *
 * It reads through the same `usePropertyDetail(id)` the detail screen used.
 * That query runs with `staleTime: Infinity` and every automatic refetch off,
 * so arriving here from a listing is served entirely from cache — which
 * matters because `GET /properties/:id` increments the view counter, and
 * opening the photos of a listing you are already looking at is not a second
 * view of it.
 *
 * Deep-linking straight to this route does fetch, and does count one view.
 * That is correct: it is a first look at the listing, arriving by another door.
 *
 * ---------------------------------------------------------------------------
 * Black background, not the theme surface. A photo viewer is the one place in
 * this app where the surrounding colour is a tool rather than a style:
 * anything lighter than the darkest tone in the image competes with it, and a
 * light theme's off-white makes every photograph look washed out. The status
 * bar is forced light for the same reason; the root layout's own `StatusBar`
 * restores it on the way out.
 */
export default function PropertyGalleryScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { width, height } = useWindowDimensions();

  const { id, index: indexParam } = useLocalSearchParams<{ id: string; index?: string }>();

  const { property, isLoading } = usePropertyDetail(id);
  const images = property?.gallery ?? [];

  // Parsed once, on mount. A NaN from a malformed deep link would make the
  // initial scroll throw and take the screen down with it, so anything
  // unparseable falls back to the first photo.
  const requestedIndex = useRef(
    Math.max(0, Number.parseInt(indexParam ?? '0', 10) || 0)
  ).current;

  const [index, setIndex] = useState(requestedIndex);
  const [paging, setPaging] = useState(true);

  // Read inside the scroll handler, which must not re-subscribe on every page
  // change, so it is held in a ref rather than captured in the closure.
  const widthRef = useRef(width);
  widthRef.current = width;

  const handleMomentumEnd = useCallback((event: NativeSyntheticEvent<NativeScrollEvent>) => {
    setIndex(Math.round(event.nativeEvent.contentOffset.x / widthRef.current));
  }, []);

  // A zoomed photo owns the drag; paging resumes when it snaps back. See
  // ZoomableImage for why this is React state and not a shared value.
  const handleZoomChange = useCallback((zoomed: boolean) => setPaging(!zoomed), []);

  const handleClose = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace(`/property/${id}`);
  }, [router, id]);

  if (isLoading) {
    return (
      <View className="flex-1 items-center justify-center bg-black">
        <StatusBar style="light" />
        <ActivityIndicator color="#ffffff" />
      </View>
    );
  }

  if (images.length === 0) {
    return (
      <Screen>
        <EmptyState
          title="No photos"
          description="This listing was posted without any images."
          actionLabel="Back to listing"
          onAction={handleClose}
        />
      </Screen>
    );
  }

  // Clamped after load rather than at parse time: the gallery length is
  // unknown until the property resolves, and an out-of-range deep link should
  // land on the last photo, not on an empty page.
  const safeIndex = Math.min(index, images.length - 1);
  const current = images[safeIndex];

  return (
    <View className="flex-1 bg-black">
      <StatusBar style="light" />

      <FlatList
        data={images}
        horizontal
        pagingEnabled={paging}
        scrollEnabled={paging}
        showsHorizontalScrollIndicator={false}
        keyExtractor={(item, i) => `${item.uri}-${i}`}
        initialScrollIndex={Math.min(requestedIndex, images.length - 1)}
        onMomentumScrollEnd={handleMomentumEnd}
        initialNumToRender={1}
        windowSize={3}
        getItemLayout={(_, i) => ({ length: width, offset: width * i, index: i })}
        renderItem={({ item }) => (
          <ZoomableImage
            uri={item.uri}
            width={width}
            height={height}
            onZoomChange={handleZoomChange}
          />
        )}
      />

      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Close photos"
        onPress={handleClose}
        hitSlop={12}
        className="absolute left-md h-11 w-11 items-center justify-center rounded-full bg-white/15"
        style={{ top: insets.top + 8 }}
      >
        <Ionicons name="close" size={24} color="#ffffff" />
      </Pressable>

      {/*
        Caption and counter, non-interactive so a drag that starts on them
        still reaches the photo underneath.
      */}
      <View
        className="absolute w-full items-center"
        style={{ bottom: insets.bottom + 20 }}
        pointerEvents="none"
      >
        {current?.label ? (
          <Text variant="footnote" className="mb-xs text-white">
            {current.label}
          </Text>
        ) : null}
        <Text variant="caption" className="text-white/70">
          {safeIndex + 1} of {images.length}
        </Text>
      </View>
    </View>
  );
}
