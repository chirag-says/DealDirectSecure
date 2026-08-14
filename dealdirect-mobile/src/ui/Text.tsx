import { createContext, useContext } from 'react';
import { Text as RNText, type TextProps as RNTextProps } from 'react-native';

import { typography, type TextStyleToken, type TypographyToken } from '@/theme';

/**
 * Typographic primitive.
 *
 * A variant selects size, leading, tracking and weight as a SET. Building
 * hierarchy from size alone loses the two rules the scale encodes: tracking is
 * size-specific (tight on display, loose on captions) and leading tracks size
 * inversely. Passing a raw fontSize bypasses both, so this component does not
 * accept one.
 *
 * Font family is intentionally unset so each platform resolves its own system
 * face, which already ships optical sizing and legibility tuning.
 */

export type TextVariant = TypographyToken;
export type TextTone = 'primary' | 'secondary' | 'muted' | 'accent' | 'danger' | 'success' | 'onAccent';

const variantClass: Record<TextVariant, string> = {
  display: 'text-display',
  title1: 'text-title1',
  title2: 'text-title2',
  title3: 'text-title3',
  body: 'text-body',
  bodyEmphasis: 'text-bodyEmphasis',
  callout: 'text-callout',
  subhead: 'text-subhead',
  footnote: 'text-footnote',
  caption: 'text-caption',
  overline: 'text-overline',
};

const toneClass: Record<TextTone, string> = {
  primary: 'text-text-primary',
  secondary: 'text-text-secondary',
  muted: 'text-text-muted',
  accent: 'text-accent',
  danger: 'text-danger',
  success: 'text-success',
  onAccent: 'text-text-on-accent',
};

/**
 * Per-weight font family override, read by every `Text` in the subtree.
 *
 * Every screen leaves this unset and gets the platform system face (see
 * `theme/typography.ts` for why). The Home redesign is the one place in the
 * app that commits to a single custom typeface — DM Sans — throughout, so
 * rather than threading a font prop through Hero, Section, PropertyRailCard,
 * ProjectCard and everything else Home renders (several of which,
 * `PropertyRailCard` and `ProjectCard` among them, are also used OUTSIDE Home
 * and must keep the system face there), the override is provided once at
 * Home's screen root and every `Text` beneath it picks it up automatically.
 * See `theme/fonts.ts`.
 */
export type FontOverride = Record<TextStyleToken['fontWeight'], string>;
const FontOverrideContext = createContext<FontOverride | null>(null);
export const FontOverrideProvider = FontOverrideContext.Provider;

export interface TextProps extends RNTextProps {
  variant?: TextVariant;
  tone?: TextTone;
  className?: string;
}

export function Text({
  variant = 'body',
  tone = 'primary',
  className = '',
  style,
  ...rest
}: TextProps) {
  const override = useContext(FontOverrideContext);
  const fontFamily = override?.[typography[variant].fontWeight];

  return (
    <RNText
      className={`${variantClass[variant]} ${toneClass[tone]} ${className}`}
      style={fontFamily ? [{ fontFamily }, style] : style}
      {...rest}
    />
  );
}
