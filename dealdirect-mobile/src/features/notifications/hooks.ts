import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect } from 'react';
import { AppState } from 'react-native';

import { call, notificationsEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import type { AppNotification } from '@/types/backend/notification';

/**
 * Notifications.
 *
 * ---------------------------------------------------------------------------
 * THE BADGE IS COUNTED FROM THE LIST, BECAUSE THERE IS NO COUNT ENDPOINT
 *
 * `GET /notifications` is the only read route, it returns the 100 most recent,
 * and it is NOT paginated. There is no `/unread-count`. So the badge is
 * `list.filter(unread).length`, which is exact up to 100 unread and saturates
 * beyond that — hence `99+` rather than a number this client cannot know.
 *
 * The same call therefore serves both the badge and the screen, and they share
 * one cache entry. A user with more than 100 notifications cannot reach the
 * older ones at all through this API; that is a backend limitation, not
 * something the client is hiding.
 *
 * ---------------------------------------------------------------------------
 * Refetched on foreground rather than polled. A poll spends the global rate
 * limit (500 per 15 minutes, shared across everyone behind one carrier NAT) on
 * a screen nobody is looking at. Coming back to the app is the moment the
 * count is actually read, and it is also when it is most likely to have
 * changed.
 */

const UNREAD_DISPLAY_CAP = 99;

export interface NotificationsState {
  items: AppNotification[];
  unreadCount: number;
  /** "99+" past the cap, since the list cannot report more than it holds. */
  badgeLabel: string | null;
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  refresh: () => void;
  requiresAuth: boolean;
}

export function useNotifications(): NotificationsState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: qk.notificationList(),
    queryFn: async ({ signal }) => {
      const response = await call(notificationsEndpoints.list, { signal });
      return response.notifications ?? [];
    },
    enabled: signedIn,
    staleTime: 60_000,
  });

  // Foreground refresh. Registered once and guarded on sign-in so a signed-out
  // app does not fire a 401 every time it is opened.
  useEffect(() => {
    if (!signedIn) return;

    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        void queryClient.invalidateQueries({ queryKey: qk.notificationList() });
      }
    });

    return () => subscription.remove();
  }, [signedIn, queryClient]);

  const items = query.data ?? [];
  const unreadCount = items.reduce((total, item) => (item.isRead ? total : total + 1), 0);

  return {
    items,
    unreadCount,
    badgeLabel:
      unreadCount === 0
        ? null
        : unreadCount > UNREAD_DISPLAY_CAP
          ? `${UNREAD_DISPLAY_CAP}+`
          : String(unreadCount),
    isLoading: signedIn && query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
    requiresAuth: !signedIn,
  };
}

/**
 * Marks one notification read. PATCH, not PUT.
 *
 * The website's helper calls `PUT /notifications/:id/read`, which is not
 * mounted and 404s. The route file is authoritative.
 *
 * Optimistic, because the user has just tapped the row and the badge should
 * drop with the tap rather than a round trip later.
 */
export function useMarkNotificationRead() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) => call(notificationsEndpoints.markRead, { params: { id } }),

    onMutate: async (id: ObjectId) => {
      await queryClient.cancelQueries({ queryKey: qk.notificationList() });
      const previous = queryClient.getQueryData<AppNotification[]>(qk.notificationList());

      queryClient.setQueryData<AppNotification[]>(qk.notificationList(), (current) =>
        (current ?? []).map((item) => (item._id === id ? { ...item, isRead: true } : item))
      );

      return { previous };
    },

    onError: (_error, _id, context) => {
      queryClient.setQueryData(qk.notificationList(), context?.previous);
    },

    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.notificationList() });
    },
  });

  return {
    markRead: useCallback((id: ObjectId) => mutation.mutate(id), [mutation]),
    isPending: mutation.isPending,
  };
}

/** PATCH `/notifications/mark-all/read` — not `/read-all`, which is not mounted. */
export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => call(notificationsEndpoints.markAllRead),

    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: qk.notificationList() });
      const previous = queryClient.getQueryData<AppNotification[]>(qk.notificationList());

      queryClient.setQueryData<AppNotification[]>(qk.notificationList(), (current) =>
        (current ?? []).map((item) => (item.isRead ? item : { ...item, isRead: true }))
      );

      return { previous };
    },

    onError: (_error, _vars, context) => {
      queryClient.setQueryData(qk.notificationList(), context?.previous);
    },

    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.notificationList() });
    },
  });

  return {
    markAllRead: useCallback(() => mutation.mutate(), [mutation]),
    isPending: mutation.isPending,
  };
}
