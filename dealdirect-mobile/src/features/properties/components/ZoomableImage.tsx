import { useCallback, useState } from 'react';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  runOnJS,
  useAnimatedStyle,
  useSharedValue,
  withTiming,
} from 'react-native-reanimated';

import { Image } from '@/ui';

/**
 * One pinch-and-pan zoomable photo, sized to fill its page.
 *
 * ---------------------------------------------------------------------------
 * THE CONFLICT THIS EXISTS TO RESOLVE
 *
 * The viewer is a horizontally paged list, and a one-finger drag inside it is
 * ambiguous: it could mean "next photo" or "move the zoomed image". Both
 * readings are correct depending on state, and no gesture library can guess
 * which.
 *
 * The rule: the pan gesture is DISABLED whenever the image is at rest. A
 * horizontal drag then reaches the list underneath and pages exactly as it
 * would with a plain image, because there is no competing recogniser to
 * arbitrate against. Zooming in enables pan and tells the host to stop paging;
 * zooming back out hands paging straight back.
 *
 * That is why `zoomed` is React state and not only a shared value. The pan
 * gesture's enabled flag is part of the gesture configuration, which is built
 * during render, so it has to change on a render — a shared value written on
 * the UI thread would not rebuild it.
 *
 * Double-tap toggles between fit and 2x. It is the fastest way back to a
 * usable state after a pinch that went too far, and easier one-handed than
 * pinching outward.
 *
 * Translation is NOT clamped to the image bounds. Clamping correctly needs the
 * rendered dimensions of a `contain`-fitted image, which depend on the photo's
 * own aspect ratio and are unknown until it decodes. The cost of leaving it
 * unclamped is that a hard fling can push the photo partly off screen; the
 * cost of clamping against wrong numbers is an image that fights the finger.
 * Zooming out snaps everything back, so neither state persists.
 */

const MAX_SCALE = 4;
const MIN_SCALE = 1;
const DOUBLE_TAP_SCALE = 2;

export interface ZoomableImageProps {
  uri: string;
  width: number;
  height: number;
  /** Fires when the image enters or leaves the zoomed state. */
  onZoomChange?: (zoomed: boolean) => void;
}

export function ZoomableImage({ uri, width, height, onZoomChange }: ZoomableImageProps) {
  const [zoomed, setZoomed] = useState(false);

  const scale = useSharedValue(1);
  const savedScale = useSharedValue(1);
  const translateX = useSharedValue(0);
  const translateY = useSharedValue(0);
  const savedTranslateX = useSharedValue(0);
  const savedTranslateY = useSharedValue(0);

  const applyZoom = useCallback(
    (next: boolean) => {
      setZoomed(next);
      onZoomChange?.(next);
    },
    [onZoomChange]
  );

  const reset = () => {
    'worklet';
    scale.value = withTiming(MIN_SCALE);
    savedScale.value = MIN_SCALE;
    translateX.value = withTiming(0);
    translateY.value = withTiming(0);
    savedTranslateX.value = 0;
    savedTranslateY.value = 0;
    runOnJS(applyZoom)(false);
  };

  const pinch = Gesture.Pinch()
    .onUpdate((event) => {
      const next = savedScale.value * event.scale;
      scale.value = Math.min(Math.max(next, MIN_SCALE), MAX_SCALE);
    })
    .onEnd(() => {
      // At or below fit scale there is nothing to pan, so the whole zoomed
      // state is discarded rather than left at 1.02 with a live pan gesture.
      if (scale.value <= MIN_SCALE) {
        reset();
        return;
      }
      savedScale.value = scale.value;
      runOnJS(applyZoom)(true);
    });

  const pan = Gesture.Pan()
    .enabled(zoomed)
    .maxPointers(1)
    .onBegin(() => {
      savedTranslateX.value = translateX.value;
      savedTranslateY.value = translateY.value;
    })
    .onUpdate((event) => {
      translateX.value = savedTranslateX.value + event.translationX;
      translateY.value = savedTranslateY.value + event.translationY;
    });

  const doubleTap = Gesture.Tap()
    .numberOfTaps(2)
    .onEnd(() => {
      if (scale.value > MIN_SCALE) {
        reset();
        return;
      }
      scale.value = withTiming(DOUBLE_TAP_SCALE);
      savedScale.value = DOUBLE_TAP_SCALE;
      runOnJS(applyZoom)(true);
    });

  // Pinch and pan run together: a two-finger gesture that both scales and
  // moves is one continuous action to the user. Double-tap races them so a
  // quick tap is not swallowed by a pan that has already begun.
  const gesture = Gesture.Race(doubleTap, Gesture.Simultaneous(pinch, pan));

  const style = useAnimatedStyle(() => ({
    transform: [
      { translateX: translateX.value },
      { translateY: translateY.value },
      { scale: scale.value },
    ],
  }));

  return (
    <GestureDetector gesture={gesture}>
      <Animated.View style={[{ width, height }, style]}>
        <Image uri={uri} size="full" contentFit="contain" style={{ width, height }} />
      </Animated.View>
    </GestureDetector>
  );
}
