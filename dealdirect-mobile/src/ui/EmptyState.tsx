import React from 'react';
import { View } from 'react-native';

import { Button, type ButtonVariant } from './Button';
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
  /**
   * Secondary by default: an empty LIST is a state the user can ignore, and a
   * filled button there competes with the content that arrives later.
   *
   * Pass `primary` when this component is the whole screen and the action is
   * the only way forward — the auth flow's terminal states ("Code sent",
   * "Password updated") are exactly that, and an outlined button as the sole
   * control on a screen reads as tentative.
   */
  actionVariant?: ButtonVariant;
  /**
   * Sits at the top of a scroll instead of filling and centring the screen.
   *
   * Mirrors `SignInPrompt.compact`, and exists for the same reason: a screen
   * that has something ELSE to offer an empty-handed user — Saved shows their
   * recently viewed listings — cannot hand the whole viewport to the box
   * explaining why the list is empty.
   */
  compact?: boolean;
}

export function EmptyState({
  title,
  description,
  actionLabel,
  onAction,
  icon,
  actionVariant = 'secondary',
  compact = false,
}: EmptyStateProps) {
  return (
    <View
      className={
        compact
          ? 'items-center px-xl py-xl'
          : 'flex-1 items-center justify-center px-xl py-2xl'
      }
    >
      {icon ? <View className="mb-base">{icon}</View> : null}

      <Text variant="title3" className="text-center">
        {title}
      </Text>

      {description ? (
        <Text variant="callout" tone="secondary" className="mt-sm text-center">
          {description}
        </Text>
      ) : null}

      {/* `align="center"` is load-bearing: without it the button inherits
          Button's default `self-start`, which overrides this container's
          `items-center` and pins the action to the left edge. */}
      {actionLabel && onAction ? (
        <Button
          label={actionLabel}
          variant={actionVariant}
          align="center"
          onPress={onAction}
          className="mt-lg"
        />
      ) : null}
    </View>
  );
}
