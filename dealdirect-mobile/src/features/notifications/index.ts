/**
 * Notifications. Cross-feature imports come through this file only.
 */

export {
  useNotifications,
  useMarkNotificationRead,
  useMarkAllNotificationsRead,
  type NotificationsState,
} from './hooks';
export { resolveNotificationTarget, type NotificationTarget } from './targets';
export { NotificationRow, type NotificationRowProps } from './components/NotificationRow';
