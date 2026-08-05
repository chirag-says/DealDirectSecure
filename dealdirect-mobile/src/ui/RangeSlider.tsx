import React, { useCallback, useState } from 'react';
import { View } from 'react-native';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  runOnJS,
  useAnimatedStyle,
  useDerivedValue,
  useSharedValue,
  withSpring,
} from 'react-native-reanimated';

import { spring, useTheme } from '@/theme';
import { Text } from './Text';

/**
 * Two-thumb range slider, for the price filter.
 *
 * Each thumb tracks 1:1 with the finger and respects the offset from WHERE it
 * was grabbed. Snapping the thumb to the touch point on grab is the single most
 * common way this control breaks the illusion of direct manipulation.
 *
 * The committed value is reported on release, not on every frame: the label
 * updates continuously so the user sees the change, while the expensive
 * consumer (a network query) fires once. Feedback during, commit at the end.
 *
 * Thumbs cannot cross; each is clamped against the other.
 */

const THUMB_SIZE = 28;
const TRACK_HEIGHT = 4;

export interface RangeSliderProps {
  min: number;
  max: number;
  /** Committed values. Uncontrolled during the drag itself. */
  value: [number, number];
  onChange: (value: [number, number]) => void;
  step?: number;
  /** Formats the live readout above the track. */
  format?: (value: number) => string;
  label?: string;
}

export function RangeSlider({
  min,
  max,
  value,
  onChange,
  step = 1,
  format = (v) => String(v),
  label,
}: RangeSliderProps) {
  const theme = useTheme();
  const [width, setWidth] = useState(0);
  const [display, setDisplay] = useState<[number, number]>(value);

  const usable = Math.max(width - THUMB_SIZE, 1);

  const toPosition = useCallback(
    (v: number) => ((v - min) / (max - min)) * usable,
    [min, max, usable]
  );

  const lowX = useSharedValue(0);
  const highX = useSharedValue(0);
  const startLow = useSharedValue(0);
  const startHigh = useSharedValue(0);

  // Re-seed positions when the container is measured or the committed value
  // changes from outside.
  React.useEffect(() => {
    if (width === 0) return;
    lowX.value = toPosition(value[0]);
    highX.value = toPosition(value[1]);
    setDisplay(value);
  }, [width, value, toPosition, lowX, highX]);

  const toValue = useCallback(
    (position: number): number => {
      'worklet';
      const ratio = position / usable;
      const raw = min + ratio * (max - min);
      const stepped = Math.round(raw / step) * step;
      return Math.min(max, Math.max(min, stepped));
    },
    [min, max, step, usable]
  );

  const updateDisplay = useCallback((low: number, high: number) => {
    setDisplay([low, high]);
  }, []);

  const commit = useCallback(
    (low: number, high: number) => {
      onChange([low, high]);
    },
    [onChange]
  );

  const lowGesture = Gesture.Pan()
    .onStart(() => {
      startLow.value = lowX.value;
    })
    .onUpdate((event) => {
      const next = Math.min(Math.max(startLow.value + event.translationX, 0), highX.value);
      lowX.value = next;
      runOnJS(updateDisplay)(toValue(next), toValue(highX.value));
    })
    .onEnd(() => {
      // Settle to the stepped position so the thumb rests on a real value.
      const settled = toPosition(toValue(lowX.value));
      lowX.value = withSpring(settled, {
        dampingRatio: spring.quick.dampingRatio,
        duration: spring.quick.duration,
      });
      runOnJS(commit)(toValue(lowX.value), toValue(highX.value));
    });

  const highGesture = Gesture.Pan()
    .onStart(() => {
      startHigh.value = highX.value;
    })
    .onUpdate((event) => {
      const next = Math.min(Math.max(startHigh.value + event.translationX, lowX.value), usable);
      highX.value = next;
      runOnJS(updateDisplay)(toValue(lowX.value), toValue(next));
    })
    .onEnd(() => {
      const settled = toPosition(toValue(highX.value));
      highX.value = withSpring(settled, {
        dampingRatio: spring.quick.dampingRatio,
        duration: spring.quick.duration,
      });
      runOnJS(commit)(toValue(lowX.value), toValue(highX.value));
    });

  const lowStyle = useAnimatedStyle(() => ({ transform: [{ translateX: lowX.value }] }));
  const highStyle = useAnimatedStyle(() => ({ transform: [{ translateX: highX.value }] }));

  const fillWidth = useDerivedValue(() => Math.max(highX.value - lowX.value, 0));
  const fillStyle = useAnimatedStyle(() => ({
    left: lowX.value + THUMB_SIZE / 2,
    width: fillWidth.value,
  }));

  const thumbStyle = {
    width: THUMB_SIZE,
    height: THUMB_SIZE,
    borderRadius: THUMB_SIZE / 2,
    backgroundColor: theme.colors.surface,
    borderWidth: 2,
    borderColor: theme.colors.accent,
    shadowColor: '#000',
    shadowOpacity: theme.elevation.card.shadowOpacity,
    shadowRadius: theme.elevation.card.shadowRadius,
    shadowOffset: { width: 0, height: theme.elevation.card.shadowOffsetY },
    elevation: theme.elevation.card.elevation,
  } as const;

  return (
    <View>
      {label ? (
        <Text variant="subhead" tone="secondary" className="mb-xs">
          {label}
        </Text>
      ) : null}

      <View className="mb-sm flex-row justify-between">
        <Text variant="bodyEmphasis">{format(display[0])}</Text>
        <Text variant="bodyEmphasis">{format(display[1])}</Text>
      </View>

      <View
        className="justify-center"
        style={{ height: THUMB_SIZE }}
        onLayout={(event) => setWidth(event.nativeEvent.layout.width)}
      >
        <View
          className="absolute rounded-full bg-surface-muted"
          style={{ height: TRACK_HEIGHT, left: THUMB_SIZE / 2, right: THUMB_SIZE / 2 }}
        />

        <Animated.View
          className="absolute rounded-full bg-accent"
          style={[{ height: TRACK_HEIGHT }, fillStyle]}
        />

        <GestureDetector gesture={lowGesture}>
          <Animated.View
            accessibilityRole="adjustable"
            accessibilityLabel={`Minimum ${format(display[0])}`}
            className="absolute"
            style={[thumbStyle, lowStyle]}
          />
        </GestureDetector>

        <GestureDetector gesture={highGesture}>
          <Animated.View
            accessibilityRole="adjustable"
            accessibilityLabel={`Maximum ${format(display[1])}`}
            className="absolute"
            style={[thumbStyle, highStyle]}
          />
        </GestureDetector>
      </View>
    </View>
  );
}
