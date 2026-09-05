import { FlashList } from '@shopify/flash-list';
import { useRouter } from 'expo-router';
import { useCallback } from 'react';
import { RefreshControl, View } from 'react-native';

import { track } from '@/analytics';
import { SignInPrompt } from '@/auth';
import {
  hrefForTarget,
  NotificationRow,
  readNotificationKind,
  resolveNotificationTarget,
  useMarkAllNotificationsRead,
  useMarkNotificationRead,
  useNotifications,
} from '@/features/notifications';
import { tabBarClearance, useTheme } from '@/theme';
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
 * Updates — the event inbox.
 *
 * Promoted from a stack route to a tab on 2026-08-24. It used to be reachable
 * only through a bell inside Home's hero, which is a website's idea of what a
 * notification is: a thing you go and look at if you happen to think of it.
 * Everything the platform has to tell a user arrives here — a lead on your
 * listing, a saved-search match, a deal approved, a reward to claim — and none
 * of it is worth less than the search field it used to sit beside.
 *
 * WHAT THIS SCREEN DOES NOT CLAIM: the count in the subtitle is derived from
 * the rows this screen already holds, not from a server-side unread endpoint,
 * because there is no such endpoint. `GET /notifications` returns the 100 most
 * recent with no cursor and no count, so "unread" here means "unread among the
 * hundred most recent". That is also why there is no dock badge yet: a badge
 * that only becomes true after you open the screen it is meant to send you to
 * is worse than no badge. Both wait on a real `unread-count` route.
 *
 * Not paginated, for the same reason: there is nothing below the hundredth row
 * to fetch, so no "load more" is offered.
 *
 * Tapping a row marks it read and navigates when the notification names a
 * destination this app recognises. It never follows an arbitrary `actionUrl`;
 * see `features/notifications/targets.ts` for why that matters.
 */
export default function UpdatesScreen() {
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
      track('notification_opened', {
        kind: readNotificationKind(notification.data) ?? target?.kind ?? 'unknown',
      });
      if (target) router.push(hrefForTarget(target));
    },
    [markRead, router]
  );

  return (
    <Screen edges={['top']}>
      {/* A root tab has nowhere to go back TO, so no back affordance. */}
      <ScreenHeader
        title="Updates"
        showBack={false}
        tight
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
          // The dock floats over this list rather than sitting below it, so
          // the last row has to clear it — every tab screen pays this.
          contentContainerStyle={{ paddingBottom: tabBarClearance }}
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
