import { FlashList } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import { useCallback } from 'react';
import { RefreshControl, View } from 'react-native';

import { SignInPrompt } from '@/auth';
import {
  NotificationRow,
  resolveNotificationTarget,
  useMarkAllNotificationsRead,
  useMarkNotificationRead,
  useNotifications,
} from '@/features/notifications';
import { useTheme } from '@/theme';
import type { AppNotification } from '@/types/backend/notification';
import {
  EmptyState,
  ErrorState,
  HeaderAction,
  Screen,
  ScreenHeader,
  Skeleton,
} from '@/ui';

/**
 * Notifications.
 *
 * Not paginated, and not because this screen chose that: `GET /notifications`
 * returns the 100 most recent and offers no cursor, so there is nothing below
 * the hundredth row to fetch. No "load more" is shown, because there is
 * nothing it could load.
 *
 * Tapping a row marks it read and navigates when the notification names a
 * destination this app recognises. It never follows an arbitrary `actionUrl`;
 * see `features/notifications/targets.ts` for why that matters.
 */
export default function NotificationsScreen() {
  const router = useRouter();
  const theme = useTheme();

  const { items, unreadCount, isLoading, isRefreshing, error, refresh, requiresAuth } =
    useNotifications();
  const { markRead } = useMarkNotificationRead();
  const { markAllRead } = useMarkAllNotificationsRead();

  const handlePress = useCallback(
    (notification: AppNotification) => {
      if (!notification.isRead) markRead(notification._id);

      const target = resolveNotificationTarget(notification);
      if (!target) return;

      if (target.kind === 'property') router.push(`/property/${target.id}`);
      else if (target.kind === 'leads') router.push('/owner/leads');
      else if (target.kind === 'dealReward') router.push(`/claim-reward/${target.verificationId}`);
      else router.push('/(tabs)/saved');
    },
    [markRead, router]
  );

  return (
    <Screen>
      <ScreenHeader
        title="Notifications"
        subtitle={unreadCount > 0 ? `${unreadCount} unread` : undefined}
        actions={
          unreadCount > 0 ? (
            <HeaderAction
              icon="checkmark-done-outline"
              label="Mark all as read"
              tone="accent"
              onPress={markAllRead}
            />
          ) : null
        }
      />

      {requiresAuth ? (
        <SignInPrompt
          icon="notifications-outline"
          title="Your notifications"
          description="Alerts about your listings, leads and saved searches appear here."
        />
      ) : isLoading ? (
        <NotificationsSkeleton />
      ) : error ? (
        <ErrorState title="Could not load notifications" onRetry={refresh} />
      ) : items.length === 0 ? (
        <EmptyState
          title="Nothing yet"
          description="You will hear from us when something happens on your listings or saved searches."
        />
      ) : (
        <FlashList
          data={items}
          keyExtractor={(item) => item._id}
          refreshControl={
            <RefreshControl
              refreshing={isRefreshing}
              onRefresh={refresh}
              tintColor={theme.colors.textMuted}
              colors={[theme.colors.accent]}
              progressBackgroundColor={theme.colors.surface}
            />
          }
          ItemSeparatorComponent={() => <View className="h-px bg-border" />}
          contentContainerStyle={{ paddingBottom: 32 }}
          renderItem={({ item }) => <NotificationRow notification={item} onPress={handlePress} />}
        />
      )}
    </Screen>
  );
}

function NotificationsSkeleton() {
  return (
    <View className="px-base pt-sm">
      {[0, 1, 2, 3, 4, 5].map((row) => (
        <View key={row} className="py-md">
          <Skeleton width="55%" height={16} />
          <Skeleton width="85%" height={14} className="mt-sm" />
          <Skeleton width={70} height={12} className="mt-sm" />
        </View>
      ))}
    </View>
  );
}
