import React, { useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { Sheet } from './Sheet';
import { Text } from './Text';

/**
 * Single-choice selector.
 *
 * Opens a sheet rather than a platform picker so both platforms behave
 * identically and long option lists stay scrollable and searchable later. The
 * trigger states the current value; a control that shows only a placeholder
 * forces the user to open it just to remember what they chose.
 */

export interface SelectOption<T extends string> {
  label: string;
  value: T;
}

export interface SelectProps<T extends string> {
  label?: string;
  placeholder?: string;
  value?: T;
  options: readonly SelectOption<T>[];
  onChange: (value: T) => void;
  error?: string;
  disabled?: boolean;
}

export function Select<T extends string>({
  label,
  placeholder = 'Select',
  value,
  options,
  onChange,
  error,
  disabled = false,
}: SelectProps<T>) {
  const [open, setOpen] = useState(false);
  const selected = options.find((option) => option.value === value);

  return (
    <View>
      {label ? (
        <Text variant="subhead" tone="secondary" className="mb-xs">
          {label}
        </Text>
      ) : null}

      <Pressable
        accessibilityRole="button"
        accessibilityState={{ disabled, expanded: open }}
        accessibilityLabel={label ?? placeholder}
        accessibilityValue={{ text: selected?.label ?? placeholder }}
        disabled={disabled}
        onPress={() => setOpen(true)}
        className={[
          'flex-row items-center justify-between rounded-lg border bg-surface-muted px-md py-md',
          error ? 'border-danger' : 'border-border',
          disabled ? 'opacity-50' : '',
        ].join(' ')}
      >
        <Text variant="body" tone={selected ? 'primary' : 'muted'}>
          {selected?.label ?? placeholder}
        </Text>
        <Text variant="footnote" tone="muted">
          ▾
        </Text>
      </Pressable>

      <View className="min-h-lg pt-xs">
        {error ? (
          <Text variant="caption" tone="danger">
            {error}
          </Text>
        ) : null}
      </View>

      <Sheet visible={open} onClose={() => setOpen(false)} title={label} heightRatio={0.5}>
        <ScrollView>
          {options.map((option) => {
            const isSelected = option.value === value;
            return (
              <Pressable
                key={option.value}
                accessibilityRole="button"
                accessibilityState={{ selected: isSelected }}
                onPress={() => {
                  onChange(option.value);
                  setOpen(false);
                }}
                className="flex-row items-center justify-between border-b border-border py-base"
              >
                <Text variant={isSelected ? 'bodyEmphasis' : 'body'} tone={isSelected ? 'accent' : 'primary'}>
                  {option.label}
                </Text>
                {isSelected ? (
                  <Text variant="body" tone="accent">
                    ✓
                  </Text>
                ) : null}
              </Pressable>
            );
          })}
        </ScrollView>
      </Sheet>
    </View>
  );
}
