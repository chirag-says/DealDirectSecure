/**
 * Chat, as the UI consumes it.
 *
 * Flattened the same way `PropertySummary` flattens `Property`: the backend
 * models carry populate shapes, a Mongoose `Map` that only sometimes survives
 * serialisation, and two different encodings of the same text depending on
 * which field you read. Components render these flat shapes and never touch
 * `@/types/backend/chat` directly.
 */

import type { MessageType } from '@/types/backend/chat';

export interface ChatPerson {
  id: string;
  name: string;
  profileImage?: string;
}

export interface ConversationSummary {
  id: string;
  otherParticipant: ChatPerson | null;
  propertyId: string;
  propertyTitle: string;
  propertyImage?: string;
  /** Entity-decoded when it came through `Message.text`; raw text otherwise
   *  carries nothing to decode, since the backend stores it unescaped. */
  lastMessageText?: string;
  lastMessageAt?: string;
  /** True when the current user sent the last message — drives "You: …". */
  lastMessageIsMine: boolean;
  unreadCount: number;
  /** Whether the current user is this conversation's property owner. */
  isOwner: boolean;
  updatedAt?: string;
}

export type ChatMessageStatus = 'sent' | 'sending' | 'failed';

export interface ChatMessage {
  id: string;
  conversationId: string;
  senderId: string;
  senderName: string;
  senderAvatar?: string;
  /** Entity-decoded. See `decodeHtmlEntities`. */
  text: string;
  messageType: MessageType;
  createdAt: string;
  isMine: boolean;
  status: ChatMessageStatus;
  /**
   * Present only on a message this device is currently sending or just sent
   * this session — the id `useMessageThread` uses to find and update the
   * optimistic bubble in place once the REST response or a retry resolves it.
   * A message loaded from history has no need for one.
   */
  clientId?: string;
}
