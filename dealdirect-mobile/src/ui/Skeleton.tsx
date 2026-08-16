import { useEffect } from 'react';
import { View, type ViewStyle } from 'react-native';
import Animated, {
  Easing,
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withRepeat,
  withTiming,
} from 'react-native-reanimated';

/**
 * Loading placeholder.
 *
 * Used for the first load of a layout whose shape is already known. A spinner
 * is the wrong tool there: it says "something is happening" where a skeleton
 * says "this is what is arriving, and roughly how much".
 *
 * The shimmer is opacity-only. A moving highlight would be a slow looping
 * oscillation across a large surface, which is exactly the pattern reduced
 * motion exists to suppress; under that setting the pulse stops entirely and
 * the placeholder rests at a readable opacity.
 */

const PULSE_MS = 900;

export interface SkeletonProps {
  width?: ViewStyle['width'];
  height?: number;
  /** Defaults to the `md` radius; pass `9999` for a circle. */
  radius?: number;
  /** For the one thing a width/height pair cannot express: `aspectRatio`, so a
   *  placeholder can match a card whose photo is a ratio rather than a size. */
  style?: ViewStyle;
  className?: string;
}

export function Skeleton({
  width = '100%',
  height,
  radius = 10,
  style,
  className = '',
}: SkeletonProps) {
  const progress = useSharedValue(0.5);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    if (reduceMotion) {
      progress.value = 0.5;
      return;
    }
    progress.value = withRepeat(
      withTiming(1, { duration: PULSE_MS, easing: Easing.inOut(Easing.quad) }),
      -1,
      true
    );
  }, [progress, reduceMotion]);

  const animatedStyle = useAnimatedStyle(() => ({ opacity: progress.value }));

  return (
    <Animated.View
      accessibilityRole="progressbar"
      accessibilityLabel="Loading"
      className={`bg-surface-muted ${className}`}
      style={[{ width, height: height ?? (style?.aspectRatio ? undefined : 16), borderRadius: radius }, style, animatedStyle]}
    />
  );
}

/** Convenience arrangement for list placeholders. */
export function SkeletonList({ count = 4, itemHeight = 84 }: { count?: number; itemHeight?: number }) {
  return (
    <View className="gap-md">
      {Array.from({ length: count }, (_, index) => (
        <Skeleton key={index} height={itemHeight} radius={14} />
      ))}
    </View>
  );
}
