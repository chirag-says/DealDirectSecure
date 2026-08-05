import React from 'react';
import { View, type ViewProps } from 'react-native';
import { SafeAreaView, type Edge } from 'react-native-safe-area-context';

/**
 * Screen container.
 *
 * Owns the background and the safe-area inset so no screen repeats either.
 *
 * `edges` defaults to top and bottom only. Left and right are excluded because
 * a horizontally inset container fights full-bleed content such as image
 * carousels; screens that need side insets opt in.
 *
 * A screen wrapped in translucent chrome should pass `edges={['left','right']}`
 * and let its scroll view run under the bar, rather than reserving a strip.
 */

export interface ScreenProps extends ViewProps {
  edges?: readonly Edge[];
  /** Drop the safe-area wrapper entirely, for screens that manage their own. */
  unsafe?: boolean;
  className?: string;
}

export function Screen({
  edges = ['top', 'bottom'],
  unsafe = false,
  className = '',
  children,
  ...rest
}: ScreenProps) {
  if (unsafe) {
    return (
      <View className={`flex-1 bg-background ${className}`} {...rest}>
        {children}
      </View>
    );
  }

  return (
    <SafeAreaView edges={edges} className="flex-1 bg-background">
      <View className={`flex-1 ${className}`} {...rest}>
        {children}
      </View>
    </SafeAreaView>
  );
}
