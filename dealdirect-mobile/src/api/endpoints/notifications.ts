/**
 * Notification endpoints. Mounted at `/api/notifications`
 * (backend/routes/notificationRoutes.js). All behind `authMiddleware`.
 *
 * METHOD WARNING: both read routes are PATCH. The website's `notificationApi`
 * helper calls `PUT /notifications/:id/read` and `PUT /notifications/read-all`,
 * and neither path is mounted. Following that helper would produce 404s. The
 * route file is authoritative; see docs/API_CONTRACT.md.
 */

import type {
  MarkNotificationReadResponse,
  NotificationsResponse,
} from '@/types/backend/notification';
import type { ObjectId, OkEnvelope } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const notificationsEndpoints = {
  list: defineEndpoint<void, NotificationsResponse>({
    method: 'GET',
    path: '/notifications',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Hard-capped at the 100 most recent and NOT paginated. Newest first. A user with heavy ' +
      'history simply cannot reach older notifications through this route.',
  }),

  markRead: defineEndpoint<void, MarkNotificationReadResponse, { id: ObjectId }>({
    method: 'PATCH',
    path: ({ id }) => `/notifications/${id}/read`,
    auth: 'user',
    envelope: 'keyed',
    note: 'PATCH, not PUT.',
  }),

  markAllRead: defineEndpoint<void, OkEnvelope>({
    method: 'PATCH',
    path: '/notifications/mark-all/read',
    auth: 'user',
    envelope: 'ok',
    note: 'PATCH, and the path is `/mark-all/read`, not `/read-all`.',
  }),
} as const;
