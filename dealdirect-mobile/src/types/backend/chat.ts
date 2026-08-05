/**
 * Chat contract. Source: backend/models/{Conversation,Message}.js and
 * backend/controllers/chatController.js.
 */

import type { IsoDate, ObjectId, Timestamps } from './common';
import type { Property } from './property';
import type { User } from './user';

/** Participants are populated with `name email profileImage`. */
export type ChatParticipant = Pick<User, '_id' | 'name' | 'email' | 'profileImage'>;

export type MessageType =
  | 'text'
  | 'image'
  | 'file'
  | 'system'
  | 'visit_request'
  | 'visit_confirmation';

export interface Message extends Timestamps {
  _id: ObjectId;
  conversation: ObjectId;
  sender: ChatParticipant;
  /**
   * HTML-ESCAPED by the backend before storage (`escapeHtml` in
   * chatController.sendMessage), so `&`, `<`, `>`, quotes arrive as entities.
   * Decode before rendering or the entities show literally.
   *
   * Note the asymmetry: `conversation.lastMessage.text` is stored RAW, so the
   * conversation preview and the message bubble encode the same text
   * differently. Handle both in the adapter.
   */
  text: string;
  messageType: MessageType;
  attachments?: Array<{
    url?: string;
    type?: string;
    name?: string;
  }>;
  readBy?: Array<{
    user: ObjectId;
    readAt: IsoDate;
  }>;
  isDeleted?: boolean;
}

export interface Conversation extends Timestamps {
  _id: ObjectId;
  participants: ChatParticipant[];
  /** Populated with `title images address price propertyTypeName owner`. */
  property: Pick<
    Property,
    '_id' | 'title' | 'images' | 'address' | 'price' | 'propertyTypeName' | 'owner'
  >;
  lastMessage?: {
    text?: string;
    sender?: ObjectId;
    createdAt?: IsoDate;
  };
  /**
   * A Mongoose `Map`, serialised to a plain object keyed by user id. Read it
   * with the current user's id.
   */
  unreadCount?: Record<string, number>;
  isActive?: boolean;
}

/**
 * A conversation as returned by `GET /chat/conversations`, which adds three
 * computed fields the raw model does not carry.
 */
export interface ConversationSummary extends Conversation {
  otherParticipant?: ChatParticipant;
  myUnreadCount: number;
  isOwner: boolean;
}

// --- Requests -------------------------------------------------------------

/**
 * CORRECTED 2026-08-05 by reading the controller. M0 declared `ownerId` as
 * required here. The controller (chatController.js:22) destructures only
 * `propertyId` from the body — `ownerId` is NEVER READ, by explicit design
 * ("H5 FIX: ownerId is NEVER accepted from the client. Always derived from
 * the property's actual owner to prevent IDOR/spam"). Sending it is harmless
 * but pointless; declaring it required was actively misleading.
 */
export interface StartConversationRequest {
  propertyId: ObjectId;
}

export interface SendMessageRequest {
  conversationId: ObjectId;
  /** Truncated to 5000 characters and HTML-escaped by the backend. */
  text: string;
  messageType?: MessageType;
}

export interface GetMessagesParams {
  page?: number;
  /** Backend default is 50. */
  limit?: number;
}

// --- Responses ------------------------------------------------------------

export interface StartConversationResponse {
  success: true;
  conversation: Conversation;
  /** `false` when an existing conversation was returned instead of created. */
  isNew: boolean;
}

export interface ConversationsResponse {
  success: true;
  conversations: ConversationSummary[];
}

/**
 * `GET /chat/messages/:conversationId`.
 *
 * Messages arrive OLDEST-FIRST (the controller queries newest-first, then
 * reverses). There is no total or page count in this response, so "no more
 * history" must be inferred from `messages.length < limit`.
 */
export interface MessagesResponse {
  success: true;
  messages: Message[];
}

/**
 * `POST /chat/message/send`.
 *
 * WARNING: on success `message` is a Message OBJECT. On every error response
 * from this same endpoint, `message` is a STRING. Narrow on `success` before
 * touching `message`, never the reverse.
 */
export interface SendMessageResponse {
  success: true;
  message: Message;
}

export interface UnreadCountResponse {
  success: true;
  unreadCount: number;
}

/**
 * `GET /chat/socket-token`.
 *
 * A JWT valid for FIVE MINUTES, minted from the cookie session purely so the
 * Socket.IO handshake has something `jwt.verify` can check. It is not an API
 * credential and must not be cached, persisted, or sent as a bearer token.
 * Fetch it fresh on every socket connect.
 */
export interface SocketTokenResponse {
  success: true;
  token: string;
}
