import { StyleSheet, type ViewStyle } from 'react-native';

import { scrim, type ScrimName } from '@/theme';
import { Gradient } from './Gradient';

/**
 * Gradient overlay for text sitting on top of a photograph.
 *
 * This exists because the alternative does not work. The previous approach was
 * a translucent pill behind each label (`bg-black/65`), which is legible but
 * announces itself: you see a chip, then the words. A scrim is invisible as an
 * object. The image simply gets darker where the text is, the way it would if
 * the photo had been shot that way, and nothing on the card reads as chrome.
 *
 * It also solves a problem a solid fill cannot. Property photos are user
 * uploads with no art direction at all: a bright sky, a white wall, a night
 * shot, all in the same rail. A fixed-opacity chip has to be tuned for the
 * worst case and is then far too heavy on every other card. A gradient that
 * bottoms out near-opaque is safe on all of them and only actually darkens the
 * strip the text occupies.
 *
 * Absolutely positioned and non-interactive by default, so it drops between an
 * `Image` and its caption without touching either one's layout or stealing the
 * touch that belongs to the card underneath.
 */

export interface ScrimProps {
  /** Which gradient shape. Defaults to `bottom`, the card treatment. */
  variant?: ScrimName;
  /** Rounded to match the image it covers. */
  borderRadius?: number;
  style?: ViewStyle;
}

export function Scrim({ variant = 'bottom', borderRadius, style }: ScrimProps) {
  const token = scrim[variant];

  return (
    <Gradient
      // A gradient is decoration. It must never be announced, and it must never
      // absorb the press meant for the card it sits on.
      pointerEvents="none"
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      colors={token.colors}
      locations={token.locations}
      style={[
        StyleSheet.absoluteFillObject as ViewStyle,
        borderRadius ? { borderRadius } : {},
        style ?? {},
      ]}
    />
  );
}
