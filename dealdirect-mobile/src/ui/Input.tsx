import React, { forwardRef, useState } from 'react';
import { StyleSheet, TextInput, View, type TextInputProps } from 'react-native';

import { spacing, touchTarget, useTheme } from '@/theme';
import { Text } from './Text';
import { useTextInputStyle } from './textInputStyle';

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
  /**
   * Rendered inside the field, BEFORE the text, and not editable.
   *
   * For a fixed part of the value the user must see but must not type — a
   * country code being the case it was added for. Distinct from a placeholder,
   * which disappears, and from putting "+91" in the label, which leaves the
   * user unsure whether to type it.
   */
  prefix?: React.ReactNode;
  containerClassName?: string;
}

export const Input = forwardRef<TextInput, InputProps>(function Input(
  { label, error, hint, trailing, prefix, containerClassName = '', onBlur, onFocus, ...rest },
  ref
) {
  const [focused, setFocused] = useState(false);
  const theme = useTheme();
  const inputStyle = useTextInputStyle();

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
        // A field shorter than the minimum touch target is one the thumb
        // misses. Padding alone got there with the old line-box height and
        // does not without it, so the floor is stated rather than emergent.
        style={{ minHeight: touchTarget.min }}
      >
        {/*
          Separated by a hairline rather than by spacing alone. "+91 9876543210"
          with only a gap between the two reads as one number the user has half
          typed; the rule says the left part is fixed and the right part is
          theirs, which is what every Indian portal's phone field does.
        */}
        {prefix ? (
          <View
            className="mr-md flex-row items-center pr-md"
            style={{
              borderRightWidth: StyleSheet.hairlineWidth,
              borderRightColor: theme.colors.border,
              paddingVertical: spacing.md,
            }}
          >
            {typeof prefix === 'string' ? (
              <Text variant="body" tone="secondary">
                {prefix}
              </Text>
            ) : (
              prefix
            )}
          </View>
        ) : null}

        <TextInput
          ref={ref}
          /*
            The style comes from `useTextInputStyle`, NOT from `text-body`.
            That class carries a line height, and a line height on a TextInput
            clips the bottom of every descender — which is the bug this fixed.
            Read `ui/textInputStyle.ts` before changing it back.
          */
          className="flex-1"
          style={[inputStyle, { paddingVertical: spacing.md }]}
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
