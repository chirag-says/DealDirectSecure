/**
 * Notification contract. Source: backend/models/Notification.js and
 * backend/controllers/notificationController.js.
 *
 * Every saved Notification also triggers an email through a `post('save')` hook
 * on the model, provided the user has not disabled `preferences.emailNotifications`.
 * Users therefore already receive out-of-app delivery today, which is why push
 * is an enhancement rather than a functional gap.
 *
 * Read routes are PATCH, not PUT. The website's `notificationApi` helper calls
 * `PUT /notifications/:id/read` and `PUT /notifications/read-all`, neither of
 * which is mounted. See docs/API_CONTRACT.md.
 */

import type { ObjectId, Timestamps } from './common';

export interface AppNotification extends Timestamps {
  _id: ObjectId;
  user: ObjectId;
  title: string;
  message: string;
  /** Free-form. Observed values include `general`, `saved-search`, `lead`, `agreement`. */
  type: string;
  data: {
    actionUrl?: string;
    actionText?: string;
    [key: string]: unknown;
  };
  isRead: boolean;
}

/** `GET /notifications`. Hard-capped at the 100 most recent, not paginated. */
export interface NotificationsResponse {
  success: true;
  notifications: AppNotification[];
}

/** `PATCH /notifications/:id/read`. */
export interface MarkNotificationReadResponse {
  success: true;
  notification: AppNotification;
}
