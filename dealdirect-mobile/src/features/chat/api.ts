/**
 * Chat data access. The only place that calls the chat endpoints. Everything
 * above this line deals in `ConversationSummary` / `ChatMessage`, never in the
 * backend's raw shapes.
 */

import { call, chatEndpoints } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type { Message, MessageType } from '@/types/backend/chat';
import { adaptConversation, adaptMessage } from './adapters';
import type { ConversationSummary, ChatMessage } from './types';

export async function fetchConversations(
  myUserId: string,
  signal?: AbortSignal
): Promise<ConversationSummary[]> {
  const response = await call(chatEndpoints.conversations, { signal });
  return (response.conversations ?? []).map((raw) => adaptConversation(raw, myUserId));
}

/** Backend default and the only value this client ever requests. */
export const MESSAGE_PAGE_SIZE = 50;

export interface MessagePage {
  items: ChatMessage[];
  /** This page's own page number, so the hook can request the next OLDER one. */
  page: number;
  hasMore: boolean;
}

/**
 * One page of history.
 *
 * `page=1` is the newest 50, oldest-first WITHIN that page; `page=2` is the
 * 50 before that, also oldest-first within itself. There is no `total`, so
 * "no older history" is inferred the only way it can be: a page shorter than
 * the size requested. The hook that consumes this is what stitches pages back
 * into one oldest-first list — see `useMessageThread`.
 */
export async function fetchMessagePage(
  conversationId: ObjectId,
  page: number,
  myUserId: string,
  signal?: AbortSignal
): Promise<MessagePage> {
  const response = await call(chatEndpoints.messages, {
    params: { conversationId },
    data: { page, limit: MESSAGE_PAGE_SIZE },
    signal,
  });

  const items = (response.messages ?? []).map((raw) => adaptMessage(raw, myUserId));
  return { items, page, hasMore: items.length === MESSAGE_PAGE_SIZE };
}

export interface SentMessage {
  message: ChatMessage;
  /**
   * Phase 2: when the text tripped the server's lure heuristics, the system
   * warning it saved to the thread. Both parties see it; the sender gets it
   * here, the other party gets it over the socket (see `useMessageThread`).
   */
  warning: ChatMessage | null;
  /**
   * The backend objects, untouched, for the socket fan-out. The receiving
   * client checks the relayed payload with `isMessageShape`, which wants the
   * backend's field names (`_id`, `conversation`, `sender._id`), not the
   * adapted ones. Emitting the adapted shape is silently dropped on receipt.
   */
  wire: { message: Message; warning: Message | null };
}

/**
 * Persists a message. This alone is the source of truth — see `useSendMessage`
 * for why the socket emit that follows it is fan-out only, never a substitute.
 */
export async function sendMessageRequest(
  conversationId: ObjectId,
  text: string,
  messageType: MessageType | undefined,
  myUserId: string
): Promise<SentMessage> {
  const response = await call(chatEndpoints.sendMessage, {
    data: { conversationId, text, messageType },
  });
  const warning = response.warning ?? null;
  return {
    message: adaptMessage(response.message, myUserId),
    warning: warning ? adaptMessage(warning, myUserId) : null,
    wire: { message: response.message, warning },
  };
}

/**
 * `GET /chat/messages/:conversationId` with `limit=1` marks the fetched
 * messages read as a side effect and zeroes the caller's unread count for
 * this conversation — the ONLY route on this backend that does either. Used
 * purely for that side effect, from `useMessageThread`, whenever a live
 * message arrives while the thread is open: the content is already known from
 * the socket push, so this response itself is discarded rather than merged
 * into the displayed history.
 */
export async function pingConversationRead(conversationId: ObjectId): Promise<void> {
  await call(chatEndpoints.messages, {
    params: { conversationId },
    data: { page: 1, limit: 1 },
  });
}

export async function startConversationRequest(propertyId: ObjectId) {
  const response = await call(chatEndpoints.startConversation, { data: { propertyId } });
  return { conversationId: response.conversation._id, isNew: response.isNew };
}

export async function deleteConversationRequest(conversationId: ObjectId): Promise<void> {
  await call(chatEndpoints.deleteConversation, { params: { conversationId } });
}
