import { useMemo } from 'react';
import { View } from 'react-native';

import { Input, Text, formatPrice } from '@/ui';

/**
 * A rupee amount, with the figure said back in words underneath.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ECHO LINE IS NOT DECORATION
 *
 * These fields take seven- and eight-digit numbers, and a bare `2500000` in a
 * numeric input is genuinely hard to read: the difference between twenty-five
 * lakh and two and a half crore is one keystroke and there is nothing on
 * screen to catch it. Every Indian portal's loan calculator prints the amount
 * back in lakh/crore under the field for exactly this reason, and it is the
 * cheapest error-prevention on a form of this kind — the user does not have to
 * count digits, they read a sentence.
 *
 * It renders only above a lakh. Under that the digits are already legible and
 * the echo would be noise repeating what is directly above it.
 *
 * The field itself stays a plain digit input rather than formatting as the user
 * types. Live grouping moves the caret under the finger on every keystroke,
 * which is a well-known way to make a numeric field feel broken; the echo gets
 * the same benefit without touching what the user is editing.
 */

const LAKH = 100_000;

export interface RupeeFieldProps {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  /** Sits under the echo, for anything the label cannot say in three words. */
  hint?: string;
}

export function RupeeField({ label, value, onChangeText, hint }: RupeeFieldProps) {
  const echo = useMemo(() => {
    const amount = Number(value) || 0;
    return amount >= LAKH ? formatPrice(amount) : null;
  }, [value]);

  return (
    <View>
      <Input
        label={label}
        value={value}
        onChangeText={(next) => onChangeText(next.replace(/[^0-9]/g, ''))}
        keyboardType="number-pad"
        placeholder="0"
      />

      {echo ? (
        <Text variant="caption" tone="accent" className="mt-xs">
          {echo}
        </Text>
      ) : null}

      {hint ? (
        <Text variant="caption" tone="muted" className="mt-xs">
          {hint}
        </Text>
      ) : null}
    </View>
  );
}
