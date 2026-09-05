import type { Href } from 'expo-router';

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
 * simply does not navigate, which is the correct outcome for a notification
 * whose destination cannot be verified.
 *
 * `data` is typed with an index signature, so every read here is guarded
 * rather than asserted.
 *
 * ---------------------------------------------------------------------------
 * `data.kind` FIRST, HEURISTICS SECOND (Phase 0)
 *
 * Every push and every in-app notification now carries `data.kind` from a
 * closed vocabulary (`NOTIFICATION_KINDS`), with the id the kind needs beside
 * it. `resolveTargetFromData` reads that and nothing else; it is what the push
 * tap handler uses, because a push payload has no `type` and no title to
 * guess from. `resolveNotificationTarget` tries it first and falls back to the
 * older `type`/`propertyId`/`actionUrl` reading for rows written before the
 * vocabulary existed. A `kind` outside the vocabulary, or a kind whose id is
 * missing or malformed, resolves to nothing rather than to a guess.
 *
 * ---------------------------------------------------------------------------
 * ONE HREF FUNCTION
 *
 * `hrefForTarget` is the only place a target becomes a route. Home, the
 * Updates tab and the push router all call it, so a destination changes in
 * one line and the three cannot drift.
 *
 * This file has no value imports, so it runs under `node --test` as-is; keep
 * it that way.
 */

export type NotificationTarget =
  | { kind: 'property'; id: string }
  | { kind: 'savedSearches' }
  | { kind: 'leads' }
  | { kind: 'dealReward'; verificationId: string }
  | { kind: 'deal'; leadId: string }
  | { kind: 'message'; conversationId: string; leadId?: string }
  | { kind: 'review'; verificationId: string }
  | { kind: 'digest' }
  | null;

/** `data.kind` as the backend spells it. Closed; anything else is ignored. */
export const NOTIFICATION_KINDS = [
  'property',
  'leads',
  'dealReward',
  'savedSearches',
  'deal',
  'visit',
  'message',
  'review',
  'digest',
] as const;

export type NotificationKind = (typeof NOTIFICATION_KINDS)[number];

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

/** The `kind` a payload names, if it is one this app knows. */
export function readNotificationKind(data: unknown): NotificationKind | undefined {
  if (typeof data !== 'object' || data === null) return undefined;
  const kind = (data as { kind?: unknown }).kind;
  if (typeof kind !== 'string') return undefined;
  return (NOTIFICATION_KINDS as readonly string[]).includes(kind)
    ? (kind as NotificationKind)
    : undefined;
}

/**
 * Resolves a destination from `data.kind` and its ids alone. `data` is
 * `unknown` because a push payload is exactly that: whatever the OS handed
 * over, before anything has looked at it.
 */
export function resolveTargetFromData(data: unknown): NotificationTarget {
  const kind = readNotificationKind(data);
  if (!kind) return null;

  const fields = data as Record<string, unknown>;

  switch (kind) {
    case 'property': {
      const id = readId(fields.propertyId);
      return id ? { kind: 'property', id } : null;
    }
    case 'leads':
      return { kind: 'leads' };
    case 'dealReward': {
      const verificationId = readId(fields.verificationId);
      return verificationId ? { kind: 'dealReward', verificationId } : null;
    }
    case 'savedSearches':
      // The id is not needed to land on the list, so its absence is not fatal.
      return { kind: 'savedSearches' };
    case 'deal':
    case 'visit': {
      // A visit lives on its deal; the deal screen is where it is shown.
      const leadId = readId(fields.leadId);
      return leadId ? { kind: 'deal', leadId } : null;
    }
    case 'message': {
      const conversationId = readId(fields.conversationId);
      if (!conversationId) return null;
      const leadId = readId(fields.leadId);
      return leadId ? { kind: 'message', conversationId, leadId } : { kind: 'message', conversationId };
    }
    case 'review': {
      // The review screen is keyed by the close-deal verification. A payload
      // carrying only `reviewId` names a different document, and routing that
      // id into a verification screen would 404 by construction.
      const verificationId = readId(fields.verificationId);
      return verificationId ? { kind: 'review', verificationId } : null;
    }
    case 'digest':
      return { kind: 'digest' };
  }
}

export function resolveNotificationTarget(notification: AppNotification): NotificationTarget {
  const data = notification.data ?? {};

  const fromKind = resolveTargetFromData(data);
  if (fromKind) return fromKind;

  // "New Interest on Your Property" (`type: "interest"`, propertyController.js:1599)
  // carries `propertyId`, not a lead id: there is no leadId on this
  // notification at all. Routing an owner to the PUBLIC property page for
  // their own listing is the wrong destination for this specific type; the
  // leads list is what they actually came to check.
  if (notification.type === 'interest') return { kind: 'leads' };

  // `type: "deal_reward"` (created when admin approves a close-deal
  // verification) carries `verificationId`, not a property id. Without this
  // case the notification would resolve to `null` (no `propertyId` on this
  // type at all) and be permanently unnavigable, since there is no "my
  // verifications" list screen this could otherwise be reached from.
  if (notification.type === 'deal_reward') {
    const verificationId = readId(data.verificationId);
    if (verificationId) return { kind: 'dealReward', verificationId };
  }

  const propertyId = readId(data.propertyId) ?? propertyIdFromActionUrl(data.actionUrl);
  if (propertyId) return { kind: 'property', id: propertyId };

  if (readId(data.savedSearchId)) return { kind: 'savedSearches' };

  return null;
}

/**
 * The route for a resolved target. Ids have already been validated as
 * ObjectIds by the resolver, which is what makes interpolating them here safe.
 */
export function hrefForTarget(target: NonNullable<NotificationTarget>): Href {
  switch (target.kind) {
    case 'property':
      return `/property/${target.id}`;
    case 'leads':
      return '/owner/leads';
    case 'dealReward':
      return `/claim-reward/${target.verificationId}`;
    case 'savedSearches':
      // Landing on Activity's default segment would make the user find the
      // search themselves, so the segment is named.
      return { pathname: '/(tabs)/activity', params: { segment: 'searches' } };
    case 'deal':
      return `/deal/${target.leadId}`;
    case 'message':
      // A message inside a deal is shown on the deal; only a conversation with
      // no deal behind it opens the bare thread.
      return target.leadId ? `/deal/${target.leadId}` : `/chat/${target.conversationId}`;
    case 'review':
      return `/review/${target.verificationId}`;
    case 'digest':
      return '/owner/analytics';
  }
}
