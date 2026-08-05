import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useCallback } from 'react';
import { FlatList, Pressable, RefreshControl, View } from 'react-native';

import {
  NotificationRow,
  resolveNotificationTarget,
  useMarkAllNotificationsRead,
  useMarkNotificationRead,
  useNotifications,
} from '@/features/notifications';
import { useTheme } from '@/theme';
import type { AppNotification } from '@/types/backend/notification';
import { EmptyState, ErrorState, Screen, Skeleton, Text } from '@/ui';

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
      else router.push('/(tabs)/saved');
    },
    [markRead, router]
  );

  const handleBack = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace('/(tabs)');
  }, [router]);

  return (
    <Screen>
      <View className="flex-row items-center px-lg pt-md pb-sm">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Go back"
          onPress={handleBack}
          hitSlop={12}
          className="mr-sm -ml-xs h-9 w-9 items-center justify-center"
        >
          <Ionicons name="chevron-back" size={24} color={theme.colors.textPrimary} />
        </Pressable>

        <Text variant="title2" className="flex-1">
          Notifications
        </Text>

        {unreadCount > 0 ? (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Mark all as read"
            onPress={markAllRead}
            hitSlop={8}
            style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
          >
            <Text variant="footnote" tone="accent">
              Mark all read
            </Text>
          </Pressable>
        ) : null}
      </View>

      {requiresAuth ? (
        <EmptyState
          title="Sign in to see notifications"
          description="Alerts about your listings, leads and saved searches appear here."
          actionLabel="Sign in"
          onAction={() => router.push('/(auth)/login')}
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
        <FlatList
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
    <View className="px-lg pt-sm">
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
