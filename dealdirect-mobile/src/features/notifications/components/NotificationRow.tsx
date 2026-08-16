import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { Text } from '@/ui';
import type { AppNotification } from '@/types/backend/notification';
import { resolveNotificationTarget } from '../targets';

/**
 * One notification.
 *
 * Unread is carried by a dot and by weight, not by a tinted row background. A
 * full-width tint on every unread row turns a list of ten into a solid block
 * of colour that says nothing about which one matters; a dot marks each row
 * individually and stays legible when every row is unread.
 *
 * A row without a resolvable destination is still pressable — pressing marks
 * it read, which is a real action — but it does not navigate. See `targets.ts`
 * for why an unrecognised `actionUrl` yields no destination rather than being
 * opened.
 */

/** Relative time, in the units people actually use for a notification feed. */
function timeAgo(iso: string | undefined): string {
  if (!iso) return '';

  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';

  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));

  if (seconds < 60) return 'Just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;

  return new Date(iso).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
}

export interface NotificationRowProps {
  notification: AppNotification;
  onPress: (notification: AppNotification) => void;
}

function NotificationRowComponent({ notification, onPress }: NotificationRowProps) {
  const handlePress = useCallback(() => onPress(notification), [onPress, notification]);

  const unread = !notification.isRead;
  const navigable = resolveNotificationTarget(notification) !== null;

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${notification.title}. ${notification.message}`}
      accessibilityHint={navigable ? 'Opens the related listing' : undefined}
      onPress={handlePress}
      className="flex-row px-lg py-md active:opacity-70"
    >
      <View className="w-4 pt-xs">
        {unread ? <View className="h-2 w-2 rounded-full bg-accent" /> : null}
      </View>

      <View className="flex-1">
        <Text variant={unread ? 'bodyEmphasis' : 'body'} numberOfLines={2}>
          {notification.title}
        </Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {notification.message}
        </Text>
        <Text variant="caption" tone="muted" className="mt-xs">
          {timeAgo(notification.createdAt)}
        </Text>
      </View>
    </Pressable>
  );
}

export const NotificationRow = memo(NotificationRowComponent);
