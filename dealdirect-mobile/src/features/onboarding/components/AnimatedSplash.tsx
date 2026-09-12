import { Image as ExpoImage } from 'expo-image';
import { useEffect } from 'react';
import { StyleSheet } from 'react-native';
import Animated, {
  Easing,
  runOnJS,
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withDelay,
  withSequence,
  withTiming,
} from 'react-native-reanimated';

/**
 * The launch motion (2026-09-05).
 *
 * The native splash is a static frame: the mark on white, drawn by the OS
 * before any JavaScript runs. This overlay is its continuation. It renders
 * the SAME mark at the SAME size on the SAME white, so the moment the native
 * splash comes down nothing on screen changes — and only then does it move:
 * the mark breathes in a fraction and settles, holds for a beat, and the
 * whole sheet lifts away to reveal whatever the bootstrap decided to show
 * under it (the app, or the welcome screen).
 *
 * Total choreography is a little over a second. Longer than that and a launch
 * animation stops being a greeting and starts being a wait; shorter and it
 * reads as a flicker. With the OS "reduce motion" setting on there is no
 * scale at all, only the short crossfade the rest of the app uses.
 *
 * The native splash config in `app.config.js` is the source of truth for the
 * size and the colour; `MARK_WIDTH` and `SHEET` mirror it deliberately. If
 * one changes, the other must, or the handover shows a jump.
 */

const MARK_WIDTH = 200;
const SHEET = '#FFFFFF';

const HOLD_MS = 420;
const BREATHE_MS = 520;
const LIFT_MS = 480;

export interface AnimatedSplashProps {
  onDone: () => void;
}

export function AnimatedSplash({ onDone }: AnimatedSplashProps) {
  const reduced = useReducedMotion();
  const scale = useSharedValue(1);
  const sheetOpacity = useSharedValue(1);
  const sheetShift = useSharedValue(0);

  useEffect(() => {
    const finish = () => onDone();

    if (reduced) {
      sheetOpacity.value = withDelay(
        HOLD_MS,
        withTiming(0, { duration: 220 }, (done) => {
          if (done) runOnJS(finish)();
        })
      );
      return;
    }

    // A breath: up a touch, then back to rest, so the mark reads as alive
    // rather than as a frame that has not loaded yet.
    scale.value = withSequence(
      withTiming(1.06, { duration: BREATHE_MS * 0.55, easing: Easing.out(Easing.cubic) }),
      withTiming(1, { duration: BREATHE_MS * 0.45, easing: Easing.inOut(Easing.cubic) })
    );

    // Then the sheet lifts: a fade with a small upward drift, so it reads as
    // a cover coming off rather than a light going out.
    const liftAt = BREATHE_MS + HOLD_MS;
    sheetShift.value = withDelay(liftAt, withTiming(-24, { duration: LIFT_MS, easing: Easing.in(Easing.cubic) }));
    sheetOpacity.value = withDelay(
      liftAt,
      withTiming(0, { duration: LIFT_MS, easing: Easing.in(Easing.cubic) }, (done) => {
        if (done) runOnJS(finish)();
      })
    );
  }, [reduced, onDone, scale, sheetOpacity, sheetShift]);

  const sheetStyle = useAnimatedStyle(() => ({
    opacity: sheetOpacity.value,
    transform: [{ translateY: sheetShift.value }],
  }));

  const markStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
  }));

  return (
    <Animated.View
      pointerEvents="none"
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      style={[StyleSheet.absoluteFillObject, styles.sheet, sheetStyle]}
    >
      <Animated.View style={markStyle}>
        <ExpoImage
          source={require('../../../../assets/icon.png')}
          style={{ width: MARK_WIDTH, height: MARK_WIDTH }}
          contentFit="contain"
          cachePolicy="memory"
        />
      </Animated.View>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  sheet: {
    backgroundColor: SHEET,
    alignItems: 'center',
    justifyContent: 'center',
    // Above every screen, sheet and toast: it is the cover over all of it.
    zIndex: 1000,
    elevation: 1000,
  },
});
