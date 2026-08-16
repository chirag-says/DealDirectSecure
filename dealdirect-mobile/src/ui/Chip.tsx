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
      className={[
        'self-start rounded-full border px-md py-sm',
        selected ? 'border-accent bg-accent-muted' : 'border-border bg-surface',
        // `active:` rather than a `style={({ pressed }) => …}` function: under
        // NativeWind's JSX pragma a function-valued `style` is spread into an
        // empty object and discarded, so that form never fired. See
        // `features/search/components/QuickFilterBar.tsx` for the full story.
        disabled ? 'opacity-50' : 'active:opacity-80',
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
