import { useEffect } from 'react';
import { View } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withDelay,
  withRepeat,
  withSequence,
  withTiming,
} from 'react-native-reanimated';

import { useTheme } from '@/theme';

/**
 * Three dots, staggered. Matches the `Skeleton` primitive's convention of
 * disabling the animation under reduced motion rather than removing the
 * component — the dots simply hold at a mid-opacity instead of pulsing.
 */

const DOT_COUNT = 3;
const PULSE_MS = 600;
const STAGGER_MS = 150;

function Dot({ delay, reduceMotion }: { delay: number; reduceMotion: boolean }) {
  const theme = useTheme();
  const opacity = useSharedValue(reduceMotion ? 0.6 : 0.3);

  useEffect(() => {
    if (reduceMotion) return;

    opacity.value = withDelay(
      delay,
      withRepeat(
        withSequence(
          withTiming(1, { duration: PULSE_MS / 2 }),
          withTiming(0.3, { duration: PULSE_MS / 2 })
        ),
        -1
      )
    );
  }, [delay, opacity, reduceMotion]);

  const style = useAnimatedStyle(() => ({ opacity: opacity.value }));

  return (
    <Animated.View
      style={[
        { width: 6, height: 6, borderRadius: 3, marginHorizontal: 2, backgroundColor: theme.colors.textMuted },
        style,
      ]}
    />
  );
}

export function TypingIndicator() {
  const reduceMotion = useReducedMotion();

  return (
    <View className="flex-row items-center rounded-full bg-surface-muted px-md py-sm">
      {Array.from({ length: DOT_COUNT }, (_, i) => (
        <Dot key={i} delay={i * STAGGER_MS} reduceMotion={reduceMotion} />
      ))}
    </View>
  );
}
