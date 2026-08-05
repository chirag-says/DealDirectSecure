import { View } from 'react-native';

import { Text } from './Text';

/**
 * Status pill.
 *
 * Tone is semantic, never decorative: `danger` must mean something is wrong,
 * not that the designer wanted red. Colour alone never carries the meaning, so
 * the label always states it too.
 */

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger';

const toneClass: Record<BadgeTone, string> = {
  neutral: 'bg-surface-muted',
  accent: 'bg-accent-muted',
  success: 'bg-success-muted',
  warning: 'bg-warning-muted',
  danger: 'bg-danger-muted',
};

const labelTone: Record<BadgeTone, 'primary' | 'accent' | 'success' | 'danger'> = {
  neutral: 'primary',
  accent: 'accent',
  success: 'success',
  warning: 'primary',
  danger: 'danger',
};

export interface BadgeProps {
  label: string;
  tone?: BadgeTone;
  className?: string;
}

export function Badge({ label, tone = 'neutral', className = '' }: BadgeProps) {
  return (
    <View className={`self-start rounded-full px-sm py-xs ${toneClass[tone]} ${className}`}>
      <Text variant="overline" tone={labelTone[tone]}>
        {label.toUpperCase()}
      </Text>
    </View>
  );
}
