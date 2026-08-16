import React from 'react';
import { View, type ViewProps } from 'react-native';

import { spacing, useTheme } from '@/theme';
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
  /**
   * 16pt on all four sides, ON BY DEFAULT SINCE 2026-08-15.
   *
   * It used to be off, which meant a card had padding only if its call site
   * remembered to ask — and of the 49 `<Card>`s in the app, 41 did not. The
   * Profile header is the clearest casualty: the avatar sat flush against the
   * card's top and left edges, and the rewards card below it had its own text
   * flush against all four. Nobody wrote that layout; it is what a container
   * with no padding does, forty-one times.
   *
   * A default that most call sites have to override is a bug in the default.
   * Turn it off for a card that clips media to its own edge — the property
   * cards do their own thing here and do not use this primitive at all.
   */
  padded?: boolean;
  className?: string;
}

export function Card({
  onPress,
  raised = true,
  bordered = false,
  radius = 'lg',
  padded = true,
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
      // Padding as a style rather than a class so it cannot lose a specificity
      // race with a caller's own `p-*`; call sites that set their own pass
      // `padded={false}`.
      style={[padded ? { padding: spacing.base } : null, shadowStyle]}
      {...rest}
    >
      {children}
    </View>
  );

  if (!onPress) return content;

  // Scale, not opacity. Dimming is the language of "disabled"; a card that
  // fades when you touch it reads as rejecting the touch. `PressableScale`
  // springs on press-DOWN and honours reduced motion.
  //
  // The accessible name is hoisted onto the PRESSABLE, not left on the surface
  // inside it. `Card` extends `ViewProps`, so an `accessibilityLabel` passed by
  // a caller used to typecheck and then land on the inner `View` — one node
  // below the thing a screen reader actually focuses. It read as a correctly
  // labelled control and was not one.
  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={rest.accessibilityLabel}
      accessibilityHint={rest.accessibilityHint}
      onPress={onPress}
      activeScale={0.985}
    >
      {content}
    </PressableScale>
  );
}
