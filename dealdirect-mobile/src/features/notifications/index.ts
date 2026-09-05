/**
 * Notifications. Cross-feature imports come through this file only.
 */

export {
  useNotifications,
  useMarkNotificationRead,
  useMarkAllNotificationsRead,
  type NotificationsState,
} from './hooks';
export {
  resolveNotificationTarget,
  resolveTargetFromData,
  readNotificationKind,
  hrefForTarget,
  NOTIFICATION_KINDS,
  type NotificationTarget,
  type NotificationKind,
} from './targets';
export { NotificationRow, type NotificationRowProps } from './components/NotificationRow';
