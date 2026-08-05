import React from 'react';
import { View } from 'react-native';

import { Button } from './Button';
import { Text } from './Text';

/**
 * Empty state.
 *
 * An empty list must say which of two things happened: there is nothing yet, or
 * the filters excluded everything. Those need different wording and different
 * actions, so `action` is where the way out lives. A dead end with no next step
 * is the failure mode this component exists to prevent.
 */

export interface EmptyStateProps {
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export function EmptyState({
  title,
  description,
  actionLabel,
  onAction,
  icon,
}: EmptyStateProps) {
  return (
    <View className="flex-1 items-center justify-center px-xl py-2xl">
      {icon ? <View className="mb-base">{icon}</View> : null}

      <Text variant="title3" className="text-center">
        {title}
      </Text>

      {description ? (
        <Text variant="callout" tone="secondary" className="mt-sm text-center">
          {description}
        </Text>
      ) : null}

      {actionLabel && onAction ? (
        <Button label={actionLabel} variant="secondary" onPress={onAction} className="mt-lg" />
      ) : null}
    </View>
  );
}
