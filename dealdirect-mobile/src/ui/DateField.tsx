import Ionicons from '@expo/vector-icons/Ionicons';
import type DateTimePickerType from '@react-native-community/datetimepicker';
import { useState } from 'react';
import { Pressable, View } from 'react-native';

import { optionalNativeModule } from '@/config/optionalNative';
import { radius, spacing, useTheme } from '@/theme';
import { Input } from './Input';
import { Text } from './Text';

/**
 * A date field backed by the native picker, degrading to typed text.
 *
 * ---------------------------------------------------------------------------
 * THE CONTRACT IS A `YYYY-MM-DD` STRING, BOTH WAYS
 *
 * The screens that use this — profile date of birth, listing availability —
 * already store and send an ISO date string, and the backend already expects
 * one. So this component takes and returns exactly that string and does the
 * Date ↔ string conversion internally. Nothing upstream changes; a native
 * spinner simply replaces a text box that asked the user to format a date by
 * hand and validated it with a regex.
 *
 * ---------------------------------------------------------------------------
 * DEGRADES TO THE OLD TEXT INPUT
 *
 * The picker is a native module and absent in Expo Go. Where it is missing this
 * renders the same `YYYY-MM-DD` text input the screens used before, so the
 * field still works — it just stops being a spinner. The fallback is the reason
 * the string contract matters: both paths speak the same format.
 */

const DateTimePicker = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('@react-native-community/datetimepicker').default as typeof DateTimePickerType,
  '@react-native-community/datetimepicker',
  'The native date picker is unavailable; falling back to typed entry.',
);

export interface DateFieldProps {
  label: string;
  /** `YYYY-MM-DD`, or empty for unset. */
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  /** Latest selectable date. Defaults to today, right for a birth date. */
  maximumDate?: Date;
  minimumDate?: Date;
  error?: string;
  containerClassName?: string;
}

function toDate(value: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const d = new Date(value + 'T00:00:00');
  return Number.isNaN(d.getTime()) ? null : d;
}

function toIso(date: Date): string {
  // Local components, not `toISOString`, which would shift the day across a
  // timezone for anyone east or west of UTC — a birth date must not move.
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function humanLabel(value: string): string | null {
  const date = toDate(value);
  if (!date) return null;
  return date.toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
}

export function DateField({
  label,
  value,
  onChange,
  placeholder = 'Select a date',
  maximumDate,
  minimumDate,
  error,
  containerClassName,
}: DateFieldProps) {
  const theme = useTheme();
  const [open, setOpen] = useState(false);

  // No native picker: the exact text input the screens used before.
  if (!DateTimePicker) {
    return (
      <Input
        label={label}
        placeholder="YYYY-MM-DD"
        value={value}
        onChangeText={onChange}
        keyboardType="numbers-and-punctuation"
        error={error}
        containerClassName={containerClassName}
      />
    );
  }

  const shown = humanLabel(value);

  return (
    <View className={containerClassName}>
      <Text variant="footnote" tone="secondary" className="mb-xs">
        {label}
      </Text>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={shown ? `${label}: ${shown}` : `${label}, not set`}
        onPress={() => setOpen(true)}
        className="flex-row items-center justify-between active:opacity-80"
        style={{
          height: 48,
          paddingHorizontal: spacing.base,
          borderRadius: radius.lg,
          borderWidth: 1,
          borderColor: error ? theme.colors.danger : theme.colors.border,
          backgroundColor: theme.colors.surface,
        }}
      >
        <Text variant="body" tone={shown ? 'primary' : 'muted'}>
          {shown ?? placeholder}
        </Text>
        <Ionicons name="calendar-outline" size={18} color={theme.colors.textMuted} />
      </Pressable>

      {error ? (
        <Text variant="caption" tone="danger" className="mt-xs">
          {error}
        </Text>
      ) : null}

      {open ? (
        <DateTimePicker
          value={toDate(value) ?? maximumDate ?? new Date()}
          mode="date"
          // Android shows a modal spinner and closes itself on pick; the event
          // fires once, so there is no per-frame churn.
          onChange={(event, date) => {
            setOpen(false);
            if (event.type === 'set' && date) onChange(toIso(date));
          }}
          maximumDate={maximumDate ?? new Date()}
          minimumDate={minimumDate}
        />
      ) : null}
    </View>
  );
}
