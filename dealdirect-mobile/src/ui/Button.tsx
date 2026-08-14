import React, { useCallback } from 'react';
import { ActivityIndicator, Pressable, View, type PressableProps } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withSpring,
  withTiming,
} from 'react-native-reanimated';

import { gesture, spring, timing, touchTarget, useTheme } from '@/theme';
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

const alignClass: Record<'start' | 'center' | 'end' | 'stretch', string> = {
  start: 'self-start',
  center: 'self-center',
  end: 'self-end',
  stretch: 'self-stretch',
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
  /**
   * Cross-axis alignment.
   *
   * ---------------------------------------------------------------------------
   * WHY THIS PROP EXISTS — it was a real, visible bug
   *
   * This component used to hard-code `self-start` whenever `fullWidth` was
   * false, with no way to override it. `alignSelf` BEATS the parent's
   * `alignItems`, so every button inside a centred container was silently
   * dragged to the leading edge — including the sign-in button on every guest
   * gate, the retry button on every error, and the action on every empty
   * state. Those are the most-seen screens in the app for a signed-out user,
   * and all of them looked broken.
   *
   * `self-start` is still the default, because a button with no alignment at
   * all inherits RN's `alignItems: 'stretch'` and grows to fill its row, which
   * is worse. But it is a default now, not a decree.
   */
  align?: 'start' | 'center' | 'end' | 'stretch';
  /** Rendered before the label. */
  leading?: React.ReactNode;
  className?: string;
}

/** Matches `labelTone`, resolved at render since these are theme values. */
function useSpinnerColors(): Record<ButtonVariant, string> {
  const theme = useTheme();
  return {
    primary: theme.colors.textOnAccent,
    secondary: theme.colors.textPrimary,
    ghost: theme.colors.accent,
    danger: theme.colors.textOnAccent,
  };
}

export function Button({
  label,
  variant = 'primary',
  size = 'md',
  loading = false,
  fullWidth = false,
  align,
  leading,
  disabled,
  className = '',
  onPressIn,
  onPressOut,
  ...rest
}: ButtonProps) {
  const pressed = useSharedValue(0);
  const reduceMotion = useReducedMotion();
  const spinnerColor = useSpinnerColors();
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

  /**
   * `isInert` is read HERE rather than left to the `opacity-50` class.
   *
   * This animated style is passed via `style`, which merges AFTER NativeWind's
   * compiled `className` styles — so the unconditional `opacity: 1` it used to
   * return silently overrode `isInert ? 'opacity-50' : ''` and every disabled
   * button in the app rendered at full strength. A disabled control that looks
   * enabled is worse than no disabled state at all: the user taps it, nothing
   * happens, and the app reads as broken.
   */
  const animatedStyle = useAnimatedStyle(() => {
    if (isInert) return { opacity: 0.45 };

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
  }, [reduceMotion, isInert]);

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
        alignClass[align ?? (fullWidth ? 'stretch' : 'start')],
        className,
      ].join(' ')}
      {...rest}
    >
      {loading ? (
        // Tinted to the label it replaces. The default spinner is mid-grey,
        // which all but disappears on a filled accent or danger button.
        <ActivityIndicator size="small" color={spinnerColor[variant]} />
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
