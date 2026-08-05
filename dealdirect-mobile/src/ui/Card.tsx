import React from 'react';
import { Pressable, View, type ViewProps } from 'react-native';

import { useTheme } from '@/theme';

/**
 * Surface container.
 *
 * Shadow values come from the elevation tokens rather than being written per
 * call site, so an iOS shadow and an Android elevation stay visually matched
 * despite being different underlying properties.
 */

export interface CardProps extends ViewProps {
  onPress?: () => void;
  /** Flat cards read as grouped rows; raised cards read as separate objects. */
  raised?: boolean;
  className?: string;
}

export function Card({
  onPress,
  raised = true,
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
      className={`rounded-lg border border-border bg-surface ${className}`}
      style={shadowStyle}
      {...rest}
    >
      {children}
    </View>
  );

  if (!onPress) return content;

  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => (pressed ? { opacity: 0.9 } : undefined)}
    >
      {content}
    </Pressable>
  );
}
