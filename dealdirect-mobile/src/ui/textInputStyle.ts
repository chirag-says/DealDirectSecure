import { Platform, type TextStyle } from 'react-native';

import { typography, useTheme, type TypographyToken } from '@/theme';
import { useFontFamily } from './Text';

/**
 * The text style for every `TextInput` in the app.
 *
 * ---------------------------------------------------------------------------
 * WHY A TYPOGRAPHY TOKEN CANNOT BE APPLIED TO A TEXT FIELD DIRECTLY
 *
 * This exists because of a real, reported bug: text in the login and register
 * fields was cut off along the bottom.
 *
 * `Input` and `SearchBar` styled their fields with `text-body`, the same
 * NativeWind class every paragraph uses. That class is a SET — size, tracking,
 * weight and **line height** — and the last one is the problem. React Native
 * honours `lineHeight` on a `TextInput` by laying the text out in a box of
 * exactly that height, and it does not grow that box when the font's own
 * ascent and descent need more room. `body` declares 16/24. DM Sans at 16pt
 * needs more than 24pt to clear its descenders, so the bottoms of g, y, p, j
 * and q were sliced off — and the comma and the underscore with them.
 *
 * It is not fixable by padding, because the clipping happens inside the line
 * box, not around it. The fix is to not declare a line height at all and let
 * the platform measure the font: a single-line field has one line, so there is
 * nothing a line height was buying in the first place.
 *
 * That is the whole reason this returns a hand-built object rather than
 * `typography[variant]`. Size, tracking and weight are taken from the token so
 * a field still matches the scale; `lineHeight` is deliberately dropped. If you
 * add it back, the bug comes back.
 *
 * ---------------------------------------------------------------------------
 * WHY IT ALSO SETS THE FONT FAMILY
 *
 * `FontOverrideProvider` is a context that `ui/Text.tsx` reads. `TextInput` is
 * not a `Text` and never read it, so every field in the app rendered in the
 * platform system face while everything around it rendered in DM Sans. Nobody
 * had noticed because a search field and its placeholder are short, but it is
 * the same inconsistency `theme/fonts.ts` describes fixing app-wide — it just
 * never reached the inputs.
 *
 * It compounds the clipping too: the declared 24pt line box was measured
 * against whichever face happened to render, and the two faces have different
 * metrics.
 *
 * ---------------------------------------------------------------------------
 * `includeFontPadding` IS LEFT ALONE, DELIBERATELY
 *
 * The usual advice for tightening Android text is `includeFontPadding: false`,
 * and it is exactly wrong here. That padding is derived from the font's own
 * ascent and descent and it is what stops descenders being clipped; turning it
 * off is a well-known way to CAUSE the bug this file exists to fix. The field's
 * height comes from padding and `minHeight` at the call site instead.
 */
export interface TextInputStyleOptions {
  /** Which typography token to take size, tracking and weight from. */
  variant?: TypographyToken;
  /** Overrides the token's colour. Defaults to primary label colour. */
  color?: string;
}

export function useTextInputStyle({
  variant = 'body',
  color,
}: TextInputStyleOptions = {}): TextStyle {
  const theme = useTheme();
  const token = typography[variant];
  const fontFamily = useFontFamily(token.fontWeight);

  return {
    fontSize: token.fontSize,
    letterSpacing: token.letterSpacing,
    color: color ?? theme.colors.textPrimary,
    // NO lineHeight. See the note above before adding one.
    ...(fontFamily
      ? // With a custom face the weight lives in the file, and passing both
        // makes Android synthesise a fake bold on top of an already-bold
        // outline. This is the same split `ui/Text.tsx` makes.
        { fontFamily }
      : { fontWeight: token.fontWeight }),
    /*
     * Android centres single-line input text against the field's box rather
     * than its own line box, and without this a field with vertical padding
     * sits its text high and looks clipped at the bottom even when it is not.
     * iOS already does the right thing and is left alone.
     */
    ...(Platform.OS === 'android' ? { textAlignVertical: 'center' as const } : null),
  };
}
