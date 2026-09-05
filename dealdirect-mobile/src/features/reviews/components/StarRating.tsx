import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, View } from 'react-native';

import { touchTarget, useTheme } from '@/theme';
import { Text } from '@/ui';

/**
 * Five stars: a selector when `onChange` is given, a display otherwise.
 *
 * As a selector each star is its own button with a spoken label ("3 of 5
 * stars") and a selected state, so a screen reader walks the five choices
 * rather than hearing one "adjustable" it has to swipe through. Each target
 * is the minimum touch size even though the glyph is smaller.
 *
 * As a display the whole row is one element announcing the value, and a
 * half-filled star stands in for a fractional mean.
 */

export interface StarRatingProps {
  /** 0 to 5. May be fractional when displaying a mean. */
  value: number;
  onChange?: (value: number) => void;
  label?: string;
  size?: number;
  disabled?: boolean;
}

export function StarRating({ value, onChange, label, size, disabled }: StarRatingProps) {
  const theme = useTheme();
  const glyph = size ?? (onChange ? 30 : 14);

  if (!onChange) {
    return (
      <View
        className="flex-row items-center"
        accessible
        accessibilityLabel={`${label ? `${label}: ` : ''}${value.toFixed(1)} out of 5 stars`}
      >
        {[1, 2, 3, 4, 5].map((star) => (
          <Ionicons
            key={star}
            name={value >= star ? 'star' : value >= star - 0.5 ? 'star-half' : 'star-outline'}
            size={glyph}
            color={value >= star - 0.5 ? theme.colors.warning : theme.colors.borderStrong}
          />
        ))}
      </View>
    );
  }

  return (
    <View>
      {label ? (
        <Text variant="subhead" className="mb-xs">
          {label}
        </Text>
      ) : null}
      <View className="flex-row" accessibilityRole="radiogroup">
        {[1, 2, 3, 4, 5].map((star) => {
          const filled = value >= star;
          return (
            <Pressable
              key={star}
              accessibilityRole="radio"
              accessibilityLabel={`${star} of 5 stars`}
              accessibilityState={{ selected: value === star, checked: value === star, disabled }}
              disabled={disabled}
              onPress={() => onChange(star)}
              hitSlop={4}
              style={{
                width: touchTarget.min,
                height: touchTarget.min,
                alignItems: 'center',
                justifyContent: 'center',
              }}
              className="active:opacity-60"
            >
              <Ionicons
                name={filled ? 'star' : 'star-outline'}
                size={glyph}
                color={filled ? theme.colors.warning : theme.colors.borderStrong}
              />
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}
