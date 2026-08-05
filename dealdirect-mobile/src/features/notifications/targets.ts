import type { AppNotification } from '@/types/backend/notification';

/**
 * Where a notification should take the user, if anywhere.
 *
 * ---------------------------------------------------------------------------
 * `data.actionUrl` IS SERVER-CONTROLLED TEXT AND IS NOT FOLLOWED BLINDLY
 *
 * The obvious implementation passes `actionUrl` to `Linking.openURL`. That
 * hands navigation to whatever string is in the database: a `javascript:` or
 * `file:` scheme, or an arbitrary external site, all become one tap away, and
 * notifications are created by several code paths including ones fed by user
 * input. Nothing about being in our own database makes a URL safe to open.
 *
 * So structured ids are preferred, and `actionUrl` is only consulted for a
 * path shape this app recognises. Anything else yields no target and the row
 * simply does not navigate — which is the correct outcome for a notification
 * whose destination cannot be verified.
 *
 * `data` is typed with an index signature, so every read here is guarded
 * rather than asserted.
 */

export type NotificationTarget =
  | { kind: 'property'; id: string }
  | { kind: 'savedSearches' }
  | null;

function readId(value: unknown): string | undefined {
  // Ids arrive as strings from JSON, but a Mongoose ObjectId that escaped
  // `.lean()` would serialise as an object. Only a plain string is trusted.
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  // A Mongo ObjectId is 24 hex characters. Anything else is not one, and
  // routing on it would produce a 404 screen at best.
  return /^[a-f\d]{24}$/i.test(trimmed) ? trimmed : undefined;
}

/** `/properties/<id>` on the website maps to `/property/<id>` here. */
function propertyIdFromActionUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;

  const match = /\/propert(?:y|ies)\/([a-f\d]{24})(?:[/?#]|$)/i.exec(value);
  return match?.[1];
}

export function resolveNotificationTarget(notification: AppNotification): NotificationTarget {
  const data = notification.data ?? {};

  const propertyId = readId(data.propertyId) ?? propertyIdFromActionUrl(data.actionUrl);
  if (propertyId) return { kind: 'property', id: propertyId };

  if (readId(data.savedSearchId)) return { kind: 'savedSearches' };

  return null;
}
