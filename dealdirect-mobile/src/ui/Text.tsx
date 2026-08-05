import { Text as RNText, type TextProps as RNTextProps } from 'react-native';

import type { TypographyToken } from '@/theme';

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

export interface TextProps extends RNTextProps {
  variant?: TextVariant;
  tone?: TextTone;
  className?: string;
}

export function Text({
  variant = 'body',
  tone = 'primary',
  className = '',
  ...rest
}: TextProps) {
  return <RNText className={`${variantClass[variant]} ${toneClass[tone]} ${className}`} {...rest} />;
}
