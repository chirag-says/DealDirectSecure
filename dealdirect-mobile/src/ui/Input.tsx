import React, { forwardRef, useState } from 'react';
import { TextInput, View, type TextInputProps } from 'react-native';

import { useTheme } from '@/theme';
import { Text } from './Text';

/**
 * Text field.
 *
 * Validation is shown INLINE and on blur, not held back until submit. Telling
 * someone at the end of a form that field three was wrong makes them re-derive
 * what they typed; telling them as they leave the field does not.
 *
 * The error message occupies reserved space so that showing it does not shift
 * the fields below it.
 */

export interface InputProps extends Omit<TextInputProps, 'className'> {
  label?: string;
  /** Shown in place of the hint when present, and switches the border to danger. */
  error?: string;
  hint?: string;
  /** Rendered inside the field, after the text. */
  trailing?: React.ReactNode;
  containerClassName?: string;
}

export const Input = forwardRef<TextInput, InputProps>(function Input(
  { label, error, hint, trailing, containerClassName = '', onBlur, onFocus, ...rest },
  ref
) {
  const [focused, setFocused] = useState(false);
  const theme = useTheme();

  const borderClass = error
    ? 'border-danger'
    : focused
      ? 'border-accent'
      : 'border-border';

  return (
    <View className={containerClassName}>
      {label ? (
        <Text variant="subhead" tone="secondary" className="mb-xs">
          {label}
        </Text>
      ) : null}

      <View
        className={`flex-row items-center rounded-lg border bg-surface-muted px-md ${borderClass}`}
      >
        <TextInput
          ref={ref}
          className="flex-1 py-md text-body text-text-primary"
          placeholderTextColor={theme.colors.textMuted}
          selectionColor={theme.colors.accent}
          onFocus={(event) => {
            setFocused(true);
            onFocus?.(event);
          }}
          onBlur={(event) => {
            setFocused(false);
            onBlur?.(event);
          }}
          accessibilityLabel={label}
          {...rest}
        />
        {trailing ? <View className="ml-sm">{trailing}</View> : null}
      </View>

      <View className="min-h-lg pt-xs">
        {error ? (
          <Text variant="caption" tone="danger">
            {error}
          </Text>
        ) : hint ? (
          <Text variant="caption" tone="muted">
            {hint}
          </Text>
        ) : null}
      </View>
    </View>
  );
});
