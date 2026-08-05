import React, { useCallback, useEffect } from 'react';
import { Modal, Pressable, View, useWindowDimensions } from 'react-native';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  runOnJS,
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { deceleration, gesture, spring, timing, useTheme } from '@/theme';
import { Text } from './Text';

/**
 * Bottom sheet.
 *
 * The four properties that separate a sheet that feels physical from one that
 * feels like a slideshow:
 *
 *  1. 1:1 tracking. While dragging, the sheet is glued to the finger. Feedback
 *     is continuous through the gesture, not applied once at the end.
 *  2. Interruptibility. The drag can start while the sheet is still animating,
 *     and the spring picks up from the current on-screen value rather than
 *     snapping to the target first.
 *  3. Momentum projection. The dismiss decision uses where the throw is HEADING,
 *     not where the finger happened to lift. A fast flick downward dismisses
 *     even from near the top; a slow drag past halfway also dismisses.
 *  4. Velocity handoff. The release velocity is passed into the spring, so
 *     there is no seam between dragging and animating.
 *
 * Upward drag is rubber-banded rather than hard-stopped: the sheet resists
 * progressively instead of freezing, which reads as "responsive, but there is
 * nothing more up here".
 *
 * Under reduced motion the whole thing becomes an opacity cross-fade and the
 * drag is disabled, since a large translating surface is exactly what that
 * setting exists to suppress.
 */

const RUBBER_BAND_CONSTANT = 0.55;
/** Fraction of sheet height past which a slow drag still dismisses. */
const DISMISS_THRESHOLD = 0.5;

function rubberband(overshoot: number, dimension: number): number {
  'worklet';
  return (
    (overshoot * dimension * RUBBER_BAND_CONSTANT) /
    (dimension + RUBBER_BAND_CONSTANT * Math.abs(overshoot))
  );
}

/**
 * Exponential-decay projection, matching platform scroll deceleration. The
 * textbook v^2/(2a) form is not what the platform ships and reads noticeably
 * differently.
 */
function project(velocity: number): number {
  'worklet';
  const rate = deceleration.fast;
  return (velocity / 1000) * (rate / (1 - rate));
}

export interface SheetProps {
  visible: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  /** Fraction of screen height the sheet occupies. */
  heightRatio?: number;
}

export function Sheet({
  visible,
  onClose,
  title,
  children,
  heightRatio = 0.6,
}: SheetProps) {
  const { height: screenHeight } = useWindowDimensions();
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const reduceMotion = useReducedMotion();

  const sheetHeight = Math.round(screenHeight * heightRatio) + insets.bottom;
  const translateY = useSharedValue(sheetHeight);
  const opacity = useSharedValue(0);

  const close = useCallback(() => onClose(), [onClose]);

  useEffect(() => {
    if (visible) {
      opacity.value = withTiming(1, { duration: timing.base });
      translateY.value = reduceMotion
        ? withTiming(0, { duration: timing.base })
        : withSpring(0, {
            dampingRatio: spring.sheet.dampingRatio,
            duration: spring.sheet.duration,
          });
    } else {
      opacity.value = withTiming(0, { duration: timing.fast });
      translateY.value = reduceMotion
        ? withTiming(sheetHeight, { duration: timing.fast })
        : withSpring(sheetHeight, {
            dampingRatio: spring.sheet.dampingRatio,
            duration: spring.sheet.duration,
          });
    }
  }, [visible, reduceMotion, sheetHeight, opacity, translateY]);

  const startY = useSharedValue(0);

  const panGesture = Gesture.Pan()
    .enabled(!reduceMotion)
    .activeOffsetY([-gesture.hysteresis, gesture.hysteresis])
    .onStart(() => {
      // Start from the PRESENTATION value so grabbing a sheet mid-animation
      // continues from where it visibly is instead of jumping to the target.
      startY.value = translateY.value;
    })
    .onUpdate((event) => {
      const next = startY.value + event.translationY;
      translateY.value =
        next < 0 ? rubberband(next, sheetHeight) : next;
    })
    .onEnd((event) => {
      const projected = translateY.value + project(event.velocityY);

      if (projected > sheetHeight * DISMISS_THRESHOLD) {
        translateY.value = withSpring(
          sheetHeight,
          {
            dampingRatio: spring.sheet.dampingRatio,
            duration: spring.sheet.duration,
            velocity: event.velocityY,
          },
          () => runOnJS(close)()
        );
      } else {
        translateY.value = withSpring(0, {
          dampingRatio: spring.sheet.dampingRatio,
          duration: spring.sheet.duration,
          velocity: event.velocityY,
        });
      }
    });

  const sheetStyle = useAnimatedStyle(() => ({
    transform: [{ translateY: translateY.value }],
  }));

  const scrimStyle = useAnimatedStyle(() => ({ opacity: opacity.value }));

  const { sheet } = theme.elevation;

  return (
    <Modal visible={visible} transparent animationType="none" onRequestClose={close}>
      <View className="flex-1 justify-end">
        <Animated.View
          style={[{ backgroundColor: theme.colors.scrim }, scrimStyle]}
          className="absolute inset-0"
        >
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Close"
            className="flex-1"
            onPress={close}
          />
        </Animated.View>

        <GestureDetector gesture={panGesture}>
          <Animated.View
            style={[
              {
                height: sheetHeight,
                paddingBottom: insets.bottom,
                shadowColor: '#000',
                shadowOpacity: sheet.shadowOpacity,
                shadowRadius: sheet.shadowRadius,
                shadowOffset: { width: 0, height: sheet.shadowOffsetY },
                elevation: sheet.elevation,
              },
              sheetStyle,
            ]}
            className="rounded-t-2xl bg-surface"
          >
            <View className="items-center py-md">
              <View className="h-xs w-4xl rounded-full bg-border-strong" />
            </View>

            {title ? (
              <View className="border-b border-border px-base pb-md">
                <Text variant="title3">{title}</Text>
              </View>
            ) : null}

            <View className="flex-1 px-base pt-base">{children}</View>
          </Animated.View>
        </GestureDetector>
      </View>
    </Modal>
  );
}
