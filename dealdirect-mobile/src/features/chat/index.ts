/**
 * Chat. Cross-feature imports come through this file only.
 */

export { adaptConversation, adaptMessage } from './adapters';
export {
  fetchConversations,
  fetchMessagePage,
  sendMessageRequest,
  startConversationRequest,
  deleteConversationRequest,
  MESSAGE_PAGE_SIZE,
  type MessagePage,
} from './api';
export {
  useChatConversations,
  useConversation,
  useChatUnreadCount,
  useStartConversation,
  useDeleteConversation,
  useMessageThread,
  useIsParticipantOnline,
  isMessageShape,
  type ConversationListState,
  type MessageThreadState,
} from './hooks';
export { ConversationRow, type ConversationRowProps } from './components/ConversationRow';
export { MessageBubble, type MessageBubbleProps } from './components/MessageBubble';
export { TypingIndicator } from './components/TypingIndicator';
export { ChatComposer, type ChatComposerProps } from './components/ChatComposer';
export { setActiveConversationId, getActiveConversationId } from './activeConversation';
export type {
  ChatMessage,
  ChatMessageStatus,
  ChatPerson,
  ConversationSummary,
} from './types';
