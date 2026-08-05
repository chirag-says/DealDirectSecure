import { decodeHtmlEntities } from '@/lib';
import type { ConversationSummary as RawConversationSummary, Message } from '@/types/backend/chat';
import type { ChatMessage, ChatPerson, ConversationSummary } from './types';

function adaptPerson(participant: { _id: string; name: string; profileImage?: string } | undefined): ChatPerson | null {
  if (!participant) return null;
  return { id: participant._id, name: participant.name, profileImage: participant.profileImage };
}

/**
 * The property's own cover image, the same fallback order the properties
 * feature uses: flat `images[]` first, since that is what the app already
 * displays for this listing everywhere else a conversation could reference it.
 */
function propertyImage(property: RawConversationSummary['property'] | undefined): string | undefined {
  return property?.images?.[0];
}

export function adaptConversation(
  raw: RawConversationSummary,
  myUserId: string
): ConversationSummary {
  const other =
    raw.otherParticipant ?? raw.participants.find((participant) => participant._id !== myUserId);

  return {
    id: raw._id,
    otherParticipant: adaptPerson(other),
    propertyId: raw.property?._id ?? '',
    propertyTitle: raw.property?.title ?? 'Property',
    propertyImage: propertyImage(raw.property),
    // Raw, not decoded: `lastMessage.text` is stored UNESCAPED by the
    // controller (it assigns the original `text`, not the sanitised one it
    // saves onto the Message). There is nothing here for a decoder to undo.
    lastMessageText: raw.lastMessage?.text,
    lastMessageAt: raw.lastMessage?.createdAt,
    lastMessageIsMine: raw.lastMessage?.sender === myUserId,
    unreadCount: raw.myUnreadCount,
    isOwner: raw.isOwner,
    updatedAt: raw.updatedAt,
  };
}

/**
 * Backend `Message` → `ChatMessage`.
 *
 * `text` IS decoded here, unlike the conversation preview above: the
 * controller escapes it before saving to the `Message` document specifically
 * (`escapeHtml` in `chatController.sendMessage`), so `&`, `<`, `>` and quotes
 * arrive as HTML entities and must be undone before this renders as plain
 * React Native text rather than as a literal `&amp;`.
 */
export function adaptMessage(raw: Message, myUserId: string): ChatMessage {
  return {
    id: raw._id,
    conversationId: raw.conversation,
    senderId: raw.sender._id,
    senderName: raw.sender.name,
    senderAvatar: raw.sender.profileImage,
    text: decodeHtmlEntities(raw.text),
    messageType: raw.messageType,
    createdAt: raw.createdAt,
    isMine: raw.sender._id === myUserId,
    status: 'sent',
  };
}
