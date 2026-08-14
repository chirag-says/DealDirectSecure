import React from 'react';
import { View, type ViewProps } from 'react-native';

import { useTheme } from '@/theme';
import { PressableScale } from './PressableScale';

/**
 * Surface container.
 *
 * Shadow values come from the elevation tokens rather than being written per
 * call site, so an iOS shadow and an Android elevation stay visually matched
 * despite being different underlying properties.
 */

export type CardRadius = 'md' | 'lg' | 'xl' | '2xl';

const radiusClass: Record<CardRadius, string> = {
  md: 'rounded-md',
  lg: 'rounded-lg',
  xl: 'rounded-xl',
  '2xl': 'rounded-2xl',
};

export interface CardProps extends ViewProps {
  onPress?: () => void;
  /** Flat cards read as grouped rows; raised cards read as separate objects. */
  raised?: boolean;
  /**
   * Hairline outline.
   *
   * OFF by default since 2026-08-13. It used to default on, and the comment
   * here said to prefer `bordered={false}` — which nobody did, because
   * defaults win. The page now sits far enough below `surface` on the neutral
   * ramp (`colors.canvas`) that a card separates by being brighter than its
   * background, which is how a raised thing actually looks. A card carrying
   * both a border and a shadow states its edge twice and reads as an admin
   * panel.
   *
   * Turn it back on for a surface that is NOT raised — a flat grouped
   * container sitting directly on the page, where the outline is the only
   * thing defining it.
   */
  bordered?: boolean;
  /** Larger surfaces take larger radii. See the radius tokens. */
  radius?: CardRadius;
  className?: string;
}

export function Card({
  onPress,
  raised = true,
  bordered = false,
  radius = 'lg',
  className = '',
  children,
  ...rest
}: CardProps) {
  const theme = useTheme();
  const { card } = theme.elevation;

  const shadowStyle = raised
    ? {
        shadowColor: '#000',
        shadowOpacity: card.shadowOpacity,
        shadowRadius: card.shadowRadius,
        shadowOffset: { width: 0, height: card.shadowOffsetY },
        elevation: card.elevation,
      }
    : undefined;

  const content = (
    <View
      className={[
        radiusClass[radius],
        bordered ? 'border border-border' : '',
        'bg-surface',
        className,
      ].join(' ')}
      style={shadowStyle}
      {...rest}
    >
      {children}
    </View>
  );

  if (!onPress) return content;

  // Scale, not opacity. Dimming is the language of "disabled"; a card that
  // fades when you touch it reads as rejecting the touch. `PressableScale`
  // springs on press-DOWN and honours reduced motion.
  return (
    <PressableScale accessibilityRole="button" onPress={onPress} activeScale={0.985}>
      {content}
    </PressableScale>
  );
}
