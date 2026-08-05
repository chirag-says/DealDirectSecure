import { View, type ViewProps, type ViewStyle } from 'react-native';

/**
 * Linear gradients, with no native module.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT `expo-linear-gradient`
 *
 * It is the obvious choice and it was the first implementation. It is also a
 * NATIVE module, and a native module is not free here: it cannot reach a device
 * over Metro. Adding one invalidates every installed dev client, so the whole
 * team has to rebuild and reinstall before they can see a JS-only change, and
 * `expo start --tunnel` — which ships JavaScript and nothing else — silently
 * serves a bundle the installed binary cannot run.
 *
 * React Native 0.76 added `experimental_backgroundImage` on the New
 * Architecture, which renders gradients in the platform view layer. This
 * project is already New Arch (react-native-mmkv v4 requires it), so the
 * capability is present with no dependency at all.
 *
 * That makes gradients a styling concern rather than a build concern, which is
 * what they should have been. Nobody has to rebuild anything to get a scrim.
 *
 * ---------------------------------------------------------------------------
 * THE `experimental_` PREFIX, HONESTLY
 *
 * The prop is still marked experimental upstream and could be renamed. The
 * exposure is exactly this file: it is the only place in the app that touches
 * the prop, so a rename is a one-line change here and nothing else moves. That
 * containment is the reason this is a primitive rather than a style spread at
 * each call site.
 *
 * The CSS string form is used rather than the structured `GradientValue` array
 * because the string is the shape the web platform standardised, so it is the
 * one least likely to be reshaped as this stabilises.
 */

export interface GradientProps extends Omit<ViewProps, 'style'> {
  /** Two or more CSS colors. `rgba()` is fine and is what scrims need. */
  colors: readonly string[];
  /**
   * Stop positions in 0..1, one per color. Omit for even distribution.
   *
   * Matching lengths is the caller's job: a mismatch produces a gradient that
   * silently ignores the extras rather than failing, which is worse than either
   * a crash or a correct render.
   */
  locations?: readonly number[];
  /**
   * Direction in CSS degrees. 180 is top-to-bottom, which is what a scrim
   * wants and therefore the default. 135 runs top-left to bottom-right.
   */
  angle?: number;
  style?: ViewStyle | ViewStyle[];
}

/**
 * Builds the CSS declaration.
 *
 * Exported for the rare case where a gradient has to go onto a component that
 * already owns its own root view (an `Animated.View` with a layout animation,
 * say) and cannot accept another wrapper.
 */
export function linearGradient(
  colors: readonly string[],
  locations?: readonly number[],
  angle = 180
): string {
  const stops = colors.map((color, index) => {
    const position = locations?.[index];
    // A stop with no position lets the platform distribute it, which is the
    // correct behaviour for an evenly spaced gradient. Emitting a computed
    // percentage instead would hard-code spacing the caller did not ask for.
    return position === undefined ? color : `${color} ${(position * 100).toFixed(2)}%`;
  });

  return `linear-gradient(${angle}deg, ${stops.join(', ')})`;
}

export function Gradient({ colors, locations, angle, style, ...rest }: GradientProps) {
  return (
    <View
      style={[
        style as ViewStyle,
        { experimental_backgroundImage: linearGradient(colors, locations, angle) },
      ]}
      {...rest}
    />
  );
}
