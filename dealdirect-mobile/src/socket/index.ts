/**
 * Socket transport. Cross-module imports come through this file only.
 */

export { SocketProvider } from './SocketProvider';
export {
  connectSocket,
  disconnectSocket,
  joinConversation,
  leaveConversation,
  emitSendMessage,
  emitTyping,
  emitStopTyping,
  onSocketEvent,
  useSocketStatus,
  useOnlineUserIds,
  useIsUserOnline,
  type SocketStatus,
} from './socketManager';
export type {
  ClientToServerEvents,
  ServerToClientEvents,
  UserTypingEvent,
  UserStopTypingEvent,
} from './types';
