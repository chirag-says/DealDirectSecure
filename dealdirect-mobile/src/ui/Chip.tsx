import { Pressable } from 'react-native';

import { gesture } from '@/theme';
import { Text } from './Text';

/**
 * Selectable filter chip.
 *
 * Selection is carried by fill AND weight, not by colour alone, so the state is
 * still readable with a colour-vision deficiency or in bright sunlight.
 */

export interface ChipProps {
  label: string;
  selected?: boolean;
  onPress?: () => void;
  disabled?: boolean;
  className?: string;
}

export function Chip({
  label,
  selected = false,
  onPress,
  disabled = false,
  className = '',
}: ChipProps) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ selected, disabled }}
      disabled={disabled}
      hitSlop={gesture.hitSlop}
      onPress={onPress}
      style={({ pressed }) => (pressed ? { opacity: 0.8 } : undefined)}
      className={[
        'self-start rounded-full border px-md py-sm',
        selected ? 'border-accent bg-accent-muted' : 'border-border bg-surface',
        disabled ? 'opacity-50' : '',
        className,
      ].join(' ')}
    >
      <Text
        variant={selected ? 'bodyEmphasis' : 'callout'}
        tone={selected ? 'accent' : 'secondary'}
      >
        {label}
      </Text>
    </Pressable>
  );
}
