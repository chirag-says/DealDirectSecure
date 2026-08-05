import React, { useCallback } from 'react';
import { Pressable, type PressableProps, type ViewStyle } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';

import { spring, timing } from '@/theme';

/**
 * A pressable that acknowledges the finger by shrinking slightly.
 *
 * Every press in this app used to be `opacity: 0.9` on `pressed`. That is the
 * React Native default and it is the wrong signal: fading something out is the
 * same visual language as disabling it, so a card that dims under the thumb
 * reads for an instant as unavailable. Shrinking reads as depressing a physical
 * control. Same one line of feedback, opposite meaning.
 *
 * It matters most on exactly the surfaces this redesign is built from. A large
 * photo card has no border and no fill to change, so scale is the only property
 * that can respond at all without repainting the image.
 *
 * The scale is deliberately small. 0.97 on a full-width card is about 11px of
 * travel, which is felt rather than seen; anything nearer 0.90 turns a tap into
 * an animation the user waits out.
 *
 * A spring, not a timing curve, because a press can be released mid-flight. A
 * timing curve has to either finish or snap; a spring simply gets a new target
 * and stays continuous. `spring.quick` is critically damped, so there is no
 * bounce on release, which would be motion the gesture did not earn.
 *
 * Under reduced motion the scale is dropped for a short opacity cross-fade.
 * That setting is about vestibular triggers, not about removing feedback, so
 * the press still has to be visibly acknowledged.
 */

const PRESSED_SCALE = 0.97;
const PRESSED_OPACITY = 0.86;

export interface PressableScaleProps extends Omit<PressableProps, 'style'> {
  /** Override the resting scale target. Keep it above 0.94. */
  activeScale?: number;
  style?: ViewStyle;
  children: React.ReactNode;
}

const AnimatedPressable = Animated.createAnimatedComponent(Pressable);

export function PressableScale({
  activeScale = PRESSED_SCALE,
  style,
  children,
  onPressIn,
  onPressOut,
  disabled,
  ...rest
}: PressableScaleProps) {
  const pressed = useSharedValue(0);
  const reduceMotion = useReducedMotion();

  const handlePressIn = useCallback<NonNullable<PressableProps['onPressIn']>>(
    (event) => {
      pressed.value = reduceMotion
        ? withTiming(1, { duration: timing.instant })
        : withSpring(1, spring.quick);
      onPressIn?.(event);
    },
    [pressed, reduceMotion, onPressIn]
  );

  const handlePressOut = useCallback<NonNullable<PressableProps['onPressOut']>>(
    (event) => {
      pressed.value = reduceMotion
        ? withTiming(0, { duration: timing.instant })
        : withSpring(0, spring.quick);
      onPressOut?.(event);
    },
    [pressed, reduceMotion, onPressOut]
  );

  const animatedStyle = useAnimatedStyle(() => {
    if (reduceMotion) {
      return {
        opacity: 1 - pressed.value * (1 - PRESSED_OPACITY),
        transform: [{ scale: 1 }],
      };
    }
    return {
      opacity: 1,
      transform: [{ scale: 1 - pressed.value * (1 - activeScale) }],
    };
  }, [activeScale, reduceMotion]);

  return (
    <AnimatedPressable
      accessibilityRole="button"
      disabled={disabled}
      onPressIn={handlePressIn}
      onPressOut={handlePressOut}
      // A disabled control must not animate, but it also must not look pressed.
      style={[style, disabled ? { opacity: 0.5 } : animatedStyle]}
      {...rest}
    >
      {children}
    </AnimatedPressable>
  );
}
