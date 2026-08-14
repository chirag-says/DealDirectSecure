import { useMutation, useQuery, useQueryClient, useInfiniteQuery } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppState } from 'react-native';

import { qk } from '@/api';
import { useAuth } from '@/auth';
import { decodeHtmlEntities } from '@/lib';
import {
  emitSendMessage,
  emitStopTyping,
  emitTyping,
  joinConversation,
  leaveConversation,
  onSocketEvent,
  useIsUserOnline,
  useSocketStatus,
} from '@/socket';
import type { ObjectId } from '@/types/backend/common';
import type { MessageType } from '@/types/backend/chat';
import {
  deleteConversationRequest,
  fetchConversations,
  fetchMessagePage,
  pingConversationRead,
  sendMessageRequest,
  startConversationRequest,
} from './api';
import type { ChatMessage, ConversationSummary } from './types';

// --- Conversation list ------------------------------------------------------

export interface ConversationListState {
  items: ConversationSummary[];
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  refresh: () => void;
  requiresAuth: boolean;
}

export function useChatConversations(): ConversationListState {
  const { status, user } = useAuth();
  const signedIn = status === 'authenticated';
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: qk.chatConversations(),
    queryFn: ({ signal }) => fetchConversations(user!._id, signal),
    enabled: signedIn,
    staleTime: 30_000,
  });

  // Foreground refresh, same reasoning as useNotifications: a poll would spend
  // the shared global rate limit on a screen nobody is looking at, so this
  // reads on the moment the user actually comes back to look.
  useEffect(() => {
    if (!signedIn) return;

    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        void queryClient.invalidateQueries({ queryKey: qk.chatConversations() });
      }
    });

    return () => subscription.remove();
  }, [signedIn, queryClient]);

  return {
    items: query.data ?? [],
    isLoading: signedIn && query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
    requiresAuth: !signedIn,
  };
}

/**
 * One conversation's summary, selected out of the list rather than fetched on
 * its own — there is no `GET /chat/conversation/:id`, only the list and the
 * message history. Triggers the same list query if nothing has fetched it
 * yet (e.g. a deep link straight into a thread), so this never renders empty
 * just because the list screen was never visited this session.
 */
export function useConversation(conversationId: ObjectId | undefined): ConversationSummary | undefined {
  const { items } = useChatConversations();
  return useMemo(() => items.find((item) => item.id === conversationId), [items, conversationId]);
}

/**
 * The Messages tab badge, summed from the list rather than from
 * `GET /chat/unread-count` — see `qk.chatConversations` for why that endpoint
 * would just be a second source of the same number.
 */
export function useChatUnreadCount(): number {
  const { items } = useChatConversations();
  return useMemo(() => items.reduce((total, item) => total + item.unreadCount, 0), [items]);
}

export function useStartConversation() {
  const mutation = useMutation({
    mutationFn: (propertyId: ObjectId) => startConversationRequest(propertyId),
  });

  return {
    start: useCallback(
      (propertyId: ObjectId) => mutation.mutateAsync(propertyId),
      [mutation]
    ),
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useDeleteConversation() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) => deleteConversationRequest(id),

    onMutate: async (id: ObjectId) => {
      await queryClient.cancelQueries({ queryKey: qk.chatConversations() });
      const previous = queryClient.getQueryData<ConversationSummary[]>(qk.chatConversations());

      queryClient.setQueryData<ConversationSummary[]>(qk.chatConversations(), (current) =>
        (current ?? []).filter((item) => item.id !== id)
      );

      return { previous };
    },

    onError: (_error, _id, context) => {
      queryClient.setQueryData(qk.chatConversations(), context?.previous);
    },

    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.chatConversations() });
    },
  });

  return {
    remove: useCallback((id: ObjectId) => mutation.mutate(id), [mutation]),
    isPending: mutation.isPending,
  };
}

// --- Message thread ----------------------------------------------------------

let clientIdCounter = 0;
function nextClientId(): string {
  clientIdCounter += 1;
  return `local-${Date.now()}-${clientIdCounter}`;
}

/** The narrowed shape `isMessageShape` guarantees, not merely `RawIncomingMessage`
 *  with its `?`s stripped — `Required<>` alone would leave every field typed
 *  `unknown`, since that is what they were declared as before narrowing. */
interface IncomingMessage {
  _id: string;
  conversation: string;
  sender: { _id: string; name: string; profileImage?: string };
  text: string;
  messageType?: string;
  createdAt: string;
}

/**
 * `receive_message`'s payload is `unknown` at the transport layer — the
 * server passes through whatever `send_message` was given verbatim. This is
 * the runtime check that stands in for the compile-time type Socket.IO cannot
 * give it, before anything here is trusted enough to adapt and render.
 */
export function isMessageShape(value: unknown): value is IncomingMessage {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  const sender = v.sender as Record<string, unknown> | undefined;

  return (
    typeof v._id === 'string' &&
    typeof v.conversation === 'string' &&
    typeof v.text === 'string' &&
    typeof v.createdAt === 'string' &&
    typeof sender === 'object' &&
    sender !== null &&
    typeof sender._id === 'string' &&
    typeof sender.name === 'string'
  );
}

export interface MessageThreadState {
  /** Oldest-first, ready to render directly into a bottom-anchored list. */
  messages: ChatMessage[];
  isLoading: boolean;
  isLoadingMore: boolean;
  hasMore: boolean;
  loadMore: () => void;
  error: unknown;
  refresh: () => void;
  send: (text: string, messageType?: MessageType) => void;
  retry: (clientId: string) => void;
  dismiss: (clientId: string) => void;
  otherUserTyping: boolean;
  notifyTyping: () => void;
  notifyStopTyping: () => void;
}

const TYPING_EMIT_INTERVAL_MS = 2000;
const TYPING_AUTO_CLEAR_MS = 4000;

/**
 * REST history plus socket liveness for one conversation, combined into one
 * flat, always-consistent message list.
 *
 * ---------------------------------------------------------------------------
 * WHY LIVE AND OPTIMISTIC MESSAGES LIVE IN ONE LOCAL ARRAY, NOT TWO
 *
 * A message this device is sending and a message the other participant just
 * sent are different in origin but identical in what the UI does with them:
 * both need to appear below the last fetched history page without a refetch,
 * and both are eventually superseded by a real REST page once one is fetched
 * again. Tracking them in one `local` array keyed by `id ?? clientId` means
 * there is exactly one code path that merges "the parts of the thread REST
 * does not know about yet" into the fetched history, instead of two.
 *
 * ---------------------------------------------------------------------------
 * PAGE ORDER
 *
 * `fetchMessagePage` documents why page 1 is the newest 50 and higher pages
 * are progressively older, each oldest-first WITHIN itself. `data.pages` is in
 * FETCH order — `[page1, page2, ...]` — so producing one oldest-first list
 * means reversing the page order before flattening, not the items within a
 * page.
 */
export function useMessageThread(conversationId: ObjectId | undefined): MessageThreadState {
  const { user } = useAuth();
  const myUserId = user?._id ?? '';
  const myName = user?.name ?? '';
  const queryClient = useQueryClient();
  const socketStatus = useSocketStatus();

  const query = useInfiniteQuery({
    queryKey: qk.chatMessages(conversationId ?? ''),
    queryFn: ({ pageParam, signal }) =>
      fetchMessagePage(conversationId as ObjectId, pageParam, myUserId, signal),
    initialPageParam: 1,
    getNextPageParam: (last) => (last.hasMore ? last.page + 1 : undefined),
    enabled: !!conversationId && !!myUserId,
    staleTime: 30_000,
  });

  // Messages REST does not know about yet: this device's own in-flight sends,
  // and anything relayed live by the socket for the other participant. Never
  // persisted — a remount re-fetches real history, which will include
  // whichever of these have since been saved.
  const [local, setLocal] = useState<ChatMessage[]>([]);

  const [otherUserTyping, setOtherUserTyping] = useState(false);
  const typingClearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTypingEmitAt = useRef(0);
  const stopTypingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Join this conversation's room whenever the socket is (or becomes) ready —
  // covers the initial mount and every reconnect after backgrounding, both of
  // which re-run this effect because `socketStatus` changes. Leaving is safe
  // to call even when the socket is not ready; it is silently dropped.
  useEffect(() => {
    if (!conversationId) return;
    joinConversation(conversationId);
    return () => leaveConversation(conversationId);
  }, [conversationId, socketStatus]);

  useEffect(() => {
    if (!conversationId) return;

    const offMessage = onSocketEvent('receive_message', (raw) => {
      if (!isMessageShape(raw) || raw.conversation !== conversationId) return;

      const message: ChatMessage = {
        id: raw._id,
        conversationId: raw.conversation,
        senderId: raw.sender._id,
        senderName: raw.sender.name,
        senderAvatar: raw.sender.profileImage,
        // The server relays the exact object `sendMessage` returned, which is
        // already HTML-entity-escaped for storage — decode it the same way
        // REST history does.
        text: decodeHtmlEntities(raw.text),
        messageType: (raw.messageType as MessageType) ?? 'text',
        createdAt: raw.createdAt,
        isMine: raw.sender._id === myUserId,
        status: 'sent',
      };

      setLocal((current) => [...current, message]);

      // The content is already known from the socket push; this call is only
      // for its side effect (marking the message read, zeroing this
      // conversation's unread count). See `pingConversationRead`.
      void pingConversationRead(conversationId).finally(() => {
        void queryClient.invalidateQueries({ queryKey: qk.chatConversations() });
      });
    });

    const offTyping = onSocketEvent('user_typing', (payload) => {
      if (payload.userId === myUserId) return;
      setOtherUserTyping(true);

      if (typingClearTimer.current) clearTimeout(typingClearTimer.current);
      // A dropped stop_typing must not leave the indicator on forever.
      typingClearTimer.current = setTimeout(() => setOtherUserTyping(false), TYPING_AUTO_CLEAR_MS);
    });

    const offStopTyping = onSocketEvent('user_stop_typing', (payload) => {
      if (payload.userId === myUserId) return;
      if (typingClearTimer.current) clearTimeout(typingClearTimer.current);
      setOtherUserTyping(false);
    });

    return () => {
      offMessage();
      offTyping();
      offStopTyping();
      if (typingClearTimer.current) clearTimeout(typingClearTimer.current);
      if (stopTypingTimer.current) clearTimeout(stopTypingTimer.current);
    };
  }, [conversationId, myUserId, queryClient]);

  const history = useMemo(() => {
    const pages = query.data?.pages ?? [];
    // Reverse PAGE order (oldest page last-fetched, first in the result), not
    // item order within a page — each page already arrives oldest-first.
    return [...pages].reverse().flatMap((p) => p.items);
  }, [query.data]);

  const messages = useMemo(() => {
    const merged = new Map<string, ChatMessage>();
    for (const item of history) merged.set(item.id, item);
    // A pending send carries the sentinel `id: ''` until the REST response
    // fills in the real one, so `||` (not `??`) is what falls through to
    // `clientId` here — an empty string is falsy but not nullish.
    for (const item of local) merged.set(item.id || item.clientId!, item);
    return Array.from(merged.values());
  }, [history, local]);

  const send = useCallback(
    (text: string, messageType?: MessageType) => {
      if (!conversationId || !myUserId) return;
      const trimmed = text.trim();
      if (!trimmed) return;

      const clientId = nextClientId();
      const optimistic: ChatMessage = {
        id: '',
        clientId,
        conversationId,
        senderId: myUserId,
        senderName: myName,
        text: trimmed,
        messageType: messageType ?? 'text',
        createdAt: new Date().toISOString(),
        isMine: true,
        status: 'sending',
      };
      setLocal((current) => [...current, optimistic]);

      sendMessageRequest(conversationId, trimmed, messageType, myUserId)
        .then((saved) => {
          setLocal((current) =>
            current.map((item) =>
              item.clientId === clientId ? { ...saved, clientId, status: 'sent' } : item
            )
          );

          // REST persisted it; the socket only has to fan it out to whoever
          // else is in the room right now. Never the other way around.
          emitSendMessage({ conversationId, message: saved });
          void queryClient.invalidateQueries({ queryKey: qk.chatConversations() });
        })
        .catch(() => {
          setLocal((current) =>
            current.map((item) =>
              item.clientId === clientId ? { ...item, status: 'failed' } : item
            )
          );
        });
    },
    [conversationId, myUserId, myName, queryClient]
  );

  const retry = useCallback(
    (clientId: string) => {
      const target = local.find((item) => item.clientId === clientId);
      if (!target) return;
      setLocal((current) => current.filter((item) => item.clientId !== clientId));
      send(target.text, target.messageType);
    },
    [local, send]
  );

  const dismiss = useCallback((clientId: string) => {
    setLocal((current) => current.filter((item) => item.clientId !== clientId));
  }, []);

  const notifyTyping = useCallback(() => {
    if (!conversationId || !myUserId) return;

    const now = Date.now();
    if (now - lastTypingEmitAt.current > TYPING_EMIT_INTERVAL_MS) {
      lastTypingEmitAt.current = now;
      emitTyping({ conversationId, userId: myUserId, userName: myName });
    }

    if (stopTypingTimer.current) clearTimeout(stopTypingTimer.current);
    stopTypingTimer.current = setTimeout(() => {
      emitStopTyping({ conversationId, userId: myUserId });
    }, TYPING_AUTO_CLEAR_MS - 1000);
  }, [conversationId, myUserId, myName]);

  const notifyStopTyping = useCallback(() => {
    if (!conversationId || !myUserId) return;
    if (stopTypingTimer.current) clearTimeout(stopTypingTimer.current);
    lastTypingEmitAt.current = 0;
    emitStopTyping({ conversationId, userId: myUserId });
  }, [conversationId, myUserId]);

  return {
    messages,
    isLoading: query.isPending,
    isLoadingMore: query.isFetchingNextPage,
    hasMore: !!query.hasNextPage,
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
    error: query.error,
    refresh: () => void query.refetch(),
    send,
    retry,
    dismiss,
    otherUserTyping,
    notifyTyping,
    notifyStopTyping,
  };
}

export { useIsUserOnline as useIsParticipantOnline };
