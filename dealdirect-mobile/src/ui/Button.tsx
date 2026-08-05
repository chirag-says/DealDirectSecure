import React, { useCallback } from 'react';
import { ActivityIndicator, Pressable, View, type PressableProps } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';

import { gesture, spring, timing, touchTarget } from '@/theme';
import { Text } from './Text';

/**
 * Button.
 *
 * Feedback lands on press-DOWN, not on release. Waiting for touch-up to show
 * anything is the single fastest way to make an interface feel dead, and the
 * cost is invisible in a screenshot.
 *
 * The scale uses a spring rather than a timing curve so that a press released
 * mid-animation is picked up from wherever it currently is instead of jumping.
 * Under reduced motion the scale is dropped and only opacity moves, which keeps
 * the feedback without the vestibular component.
 *
 * `hitSlop` widens the target past the painted bounds so a small button is
 * still comfortably tappable.
 */

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

const containerVariant: Record<ButtonVariant, string> = {
  primary: 'bg-accent',
  secondary: 'bg-surface-muted border border-border',
  ghost: 'bg-transparent',
  danger: 'bg-danger',
};

const labelTone: Record<ButtonVariant, 'onAccent' | 'primary' | 'accent'> = {
  primary: 'onAccent',
  secondary: 'primary',
  ghost: 'accent',
  danger: 'onAccent',
};

const sizeClass: Record<ButtonSize, string> = {
  sm: 'px-md py-sm rounded-md',
  md: 'px-base py-md rounded-lg',
  lg: 'px-lg py-base rounded-lg',
};

const AnimatedPressable = Animated.createAnimatedComponent(Pressable);

export interface ButtonProps extends Omit<PressableProps, 'children' | 'style'> {
  label: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  fullWidth?: boolean;
  /** Rendered before the label. */
  leading?: React.ReactNode;
  className?: string;
}

export function Button({
  label,
  variant = 'primary',
  size = 'md',
  loading = false,
  fullWidth = false,
  leading,
  disabled,
  className = '',
  onPressIn,
  onPressOut,
  ...rest
}: ButtonProps) {
  const pressed = useSharedValue(0);
  const reduceMotion = useReducedMotion();
  const isInert = disabled || loading;

  const handlePressIn = useCallback<NonNullable<PressableProps['onPressIn']>>(
    (event) => {
      pressed.value = 1;
      onPressIn?.(event);
    },
    [pressed, onPressIn]
  );

  const handlePressOut = useCallback<NonNullable<PressableProps['onPressOut']>>(
    (event) => {
      pressed.value = 0;
      onPressOut?.(event);
    },
    [pressed, onPressOut]
  );

  const animatedStyle = useAnimatedStyle(() => {
    const opacity = withTiming(pressed.value ? 0.85 : 1, { duration: timing.instant });

    if (reduceMotion) {
      return { opacity };
    }

    return {
      opacity,
      transform: [
        {
          scale: withSpring(pressed.value ? 0.97 : 1, {
            dampingRatio: spring.quick.dampingRatio,
            duration: spring.quick.duration,
          }),
        },
      ],
    };
  }, [reduceMotion]);

  return (
    <AnimatedPressable
      accessibilityRole="button"
      accessibilityState={{ disabled: Boolean(isInert), busy: loading }}
      disabled={isInert}
      hitSlop={gesture.hitSlop}
      onPressIn={handlePressIn}
      onPressOut={handlePressOut}
      style={animatedStyle}
      className={[
        'flex-row items-center justify-center',
        containerVariant[variant],
        sizeClass[size],
        fullWidth ? 'self-stretch' : 'self-start',
        isInert ? 'opacity-50' : '',
        className,
      ].join(' ')}
      {...rest}
    >
      {loading ? (
        <ActivityIndicator size="small" />
      ) : (
        <>
          {leading ? <View className="mr-sm">{leading}</View> : null}
          <Text variant="bodyEmphasis" tone={labelTone[variant]}>
            {label}
          </Text>
        </>
      )}
    </AnimatedPressable>
  );
}

/** Minimum comfortable touch target, re-exported for layout maths. */
export const MIN_TOUCH_TARGET = touchTarget.min;
