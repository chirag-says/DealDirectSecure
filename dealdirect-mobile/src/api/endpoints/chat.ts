/**
 * Chat endpoints. Mounted at `/api/chat` (backend/routes/chatRoutes.js).
 * Every route here is behind `authMiddleware` via `router.use`.
 *
 * Message flow is REST-then-socket: `sendMessage` persists and returns the
 * saved Message, and the socket `send_message` event only fans that object out
 * to the room. REST is the source of truth; the socket is delivery.
 */

import type {
  ConversationsResponse,
  GetMessagesParams,
  MessagesResponse,
  SendMessageRequest,
  SendMessageResponse,
  SocketTokenResponse,
  StartConversationRequest,
  StartConversationResponse,
  UnreadCountResponse,
} from '@/types/backend/chat';
import type { ObjectId, OkEnvelope } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const chatEndpoints = {
  /**
   * Mints the short-lived JWT the Socket.IO handshake needs.
   *
   * The cookie session token is an opaque random string, so `jwt.verify` in the
   * socket handler cannot check it. This endpoint bridges the two.
   */
  socketToken: defineEndpoint<void, SocketTokenResponse>({
    method: 'GET',
    path: '/chat/socket-token',
    auth: 'user',
    envelope: 'keyed',
    note:
      'JWT expires after FIVE MINUTES. Fetch fresh on every socket connect. Never cache it, ' +
      'never persist it, never send it as a bearer token.',
  }),

  startConversation: defineEndpoint<StartConversationRequest, StartConversationResponse>({
    method: 'POST',
    path: '/chat/conversation/start',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Idempotent: returns the existing conversation with isNew=false when one already exists ' +
      'for this buyer/property pair. 201 when created, 200 when reused.',
  }),

  conversations: defineEndpoint<void, ConversationsResponse>({
    method: 'GET',
    path: '/chat/conversations',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Adds three computed fields the model does not carry: otherParticipant, myUnreadCount, ' +
      'isOwner. Sorted by updatedAt desc. Not paginated.',
  }),

  messages: defineEndpoint<GetMessagesParams, MessagesResponse, { conversationId: ObjectId }>({
    method: 'GET',
    path: ({ conversationId }) => `/chat/messages/${conversationId}`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'Returns OLDEST-FIRST. Default limit 50. No total or page count, so end-of-history must ' +
      'be inferred from messages.length < limit. Marks fetched messages read and zeroes the ' +
      "caller's unread count as a side effect.",
  }),

  sendMessage: defineEndpoint<SendMessageRequest, SendMessageResponse>({
    method: 'POST',
    path: '/chat/message/send',
    auth: 'user',
    envelope: 'keyed',
    note:
      'On SUCCESS `message` is a Message OBJECT; on ERROR `message` is a STRING. Narrow on ' +
      '`success` first. Text is truncated to 5000 chars and HTML-escaped before storage, so ' +
      'decode entities when rendering. Emit the returned object over the socket afterwards.',
  }),

  unreadCount: defineEndpoint<void, UnreadCountResponse>({
    method: 'GET',
    path: '/chat/unread-count',
    auth: 'user',
    envelope: 'keyed',
  }),

  deleteConversation: defineEndpoint<void, OkEnvelope, { conversationId: ObjectId }>({
    method: 'DELETE',
    path: ({ conversationId }) => `/chat/conversation/${conversationId}`,
    auth: 'user',
    envelope: 'ok',
    note: 'Archives rather than hard-deletes (sets isActive=false).',
  }),
} as const;
