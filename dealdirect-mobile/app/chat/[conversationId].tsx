import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo } from 'react';
import { ActivityIndicator, FlatList, Pressable, View } from 'react-native';

import {
  ChatComposer,
  MessageBubble,
  TypingIndicator,
  setActiveConversationId,
  useConversation,
  useIsParticipantOnline,
  useMessageThread,
} from '@/features/chat';
import { useTheme } from '@/theme';
import type { ChatMessage } from '@/features/chat';
import { Avatar, EmptyState, ErrorState, KeyboardAvoider, Screen, Text } from '@/ui';

/**
 * Approximate rendered height of the header row below, used only as
 * `keyboardVerticalOffset` on iOS so the composer lands just above the
 * keyboard instead of a header's-height too low. This number is a measured
 * estimate, not a computed one — `Screen`'s SafeAreaView already accounts for
 * the notch, so this is only the header row's own height. Verify on a real
 * device before shipping; a few points off here is a visible but harmless gap,
 * not a broken layout.
 */
const HEADER_HEIGHT = 56;

/** Stable reference: an inline object here would defeat FlatList's own
 *  prop-equality bail-outs on every parent render, same reasoning
 *  `PropertyList`'s `CONTENT_CONTAINER_STYLE` documents. */
const FLATLIST_STYLE = { flex: 1 } as const;

/**
 * One conversation.
 *
 * Header data (name, avatar, property, whether the viewer owns the property)
 * comes from `useConversation`, which selects out of the conversations LIST
 * query rather than fetching this one conversation on its own — there is no
 * `GET /chat/conversation/:id` on this backend, only the list and the message
 * history. A deep link straight into a thread still works: `useConversation`
 * triggers the same list query if nothing has fetched it yet this session.
 */
export default function ChatThreadScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { conversationId } = useLocalSearchParams<{ conversationId: string }>();

  const conversation = useConversation(conversationId);
  const online = useIsParticipantOnline(conversation?.otherParticipant?.id);

  const {
    messages,
    isLoading,
    isLoadingMore,
    hasMore,
    loadMore,
    error,
    refresh,
    send,
    retry,
    dismiss,
    otherUserTyping,
    notifyTyping,
    notifyStopTyping,
  } = useMessageThread(conversationId);

  // Suppresses the M13 local-notification bridge for a message in the thread
  // the user is already looking at. Cleared on unmount so navigating away
  // (not just closing the app) lets notifications for this thread resume.
  useEffect(() => {
    setActiveConversationId(conversationId);
    return () => setActiveConversationId(null);
  }, [conversationId]);

  const handleBack = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace('/(tabs)/chat');
  }, [router]);

  const handleAccept = useCallback(
    (message: ChatMessage) => {
      send(`Site visit request accepted. ${message.text}`, 'visit_confirmation');
    },
    [send]
  );

  /**
   * Whether a `visit_request` has already been handled: true when a
   * `visit_confirmation` exists anywhere LATER in the thread. Computed with
   * one backward pass rather than an `.some()` per row, which would be
   * quadratic in the number of visit messages.
   */
  const alreadyAcceptedById = useMemo(() => {
    const result = new Map<string, boolean>();
    let seenConfirmation = false;

    for (let i = messages.length - 1; i >= 0; i -= 1) {
      const message = messages[i];
      if (!message) continue;

      if (message.messageType === 'visit_request') {
        result.set(message.id || message.clientId!, seenConfirmation);
      }
      if (message.messageType === 'visit_confirmation') {
        seenConfirmation = true;
      }
    }

    return result;
  }, [messages]);

  // Newest-first for the inverted list. Recomputed only when the underlying
  // (oldest-first) array changes, not on every render.
  const inverted = useMemo(() => [...messages].reverse(), [messages]);

  return (
    <Screen>
      <View className="flex-row items-center border-b border-border px-md py-sm">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Back to messages"
          onPress={handleBack}
          hitSlop={12}
          className="mr-sm h-9 w-9 items-center justify-center"
        >
          <Ionicons name="chevron-back" size={24} color={theme.colors.textPrimary} />
        </Pressable>

        <View>
          <Avatar
            uri={conversation?.otherParticipant?.profileImage}
            name={conversation?.otherParticipant?.name}
            size="sm"
          />
          {/* A green dot is colour-only state. The subtitle falls back to
              "Online" only when there is no property title, so with one present
              this was the sole online signal and it announced nothing. */}
          {online ? (
            <View
              accessible
              accessibilityLabel="Online"
              className="absolute bottom-0 right-0 h-2.5 w-2.5 rounded-full border-2 border-surface bg-success"
            />
          ) : null}
        </View>

        <View className="ml-sm flex-1">
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {conversation?.otherParticipant?.name ?? 'Conversation'}
          </Text>
          <Text variant="caption" tone="muted" numberOfLines={1}>
            {conversation?.propertyTitle ?? (online ? 'Online' : '')}
          </Text>
        </View>
      </View>

      {/*
        The message list AND the composer share one KeyboardAvoidingView, not
        just the composer. Wrapping the composer alone would let it float
        above the keyboard correctly while the list above it stayed the same
        height, sliding messages out from under the header instead of the
        whole block resizing together the way every native chat app behaves.
      */}
      <KeyboardAvoider keyboardVerticalOffset={HEADER_HEIGHT}>
        {isLoading ? (
          <View className="flex-1 items-center justify-center">
            <ActivityIndicator color={theme.colors.textMuted} />
          </View>
        ) : error && messages.length === 0 ? (
          <ErrorState title="Could not load this conversation" onRetry={refresh} />
        ) : messages.length === 0 ? (
          <EmptyState
            title="Say hello"
            description={
              conversation
                ? `Start the conversation about "${conversation.propertyTitle}".`
                : 'Send the first message.'
            }
          />
        ) : (
          <FlatList
            data={inverted}
            inverted
            style={FLATLIST_STYLE}
            keyExtractor={(item) => item.id || item.clientId!}
            contentContainerStyle={{ paddingVertical: 12 }}
            onEndReached={() => hasMore && loadMore()}
            onEndReachedThreshold={0.4}
            // In an INVERTED list the footer renders at the visual TOP, which
            // is where older history lives — this is the "loading more"
            // spinner, not a trailing one.
            ListFooterComponent={
              isLoadingMore ? (
                <View className="items-center py-md">
                  <ActivityIndicator size="small" color={theme.colors.textMuted} />
                </View>
              ) : null
            }
            renderItem={({ item }) => (
              <MessageBubble
                message={item}
                isOwner={!!conversation?.isOwner}
                alreadyAccepted={alreadyAcceptedById.get(item.id || item.clientId!) ?? false}
                onAccept={handleAccept}
                onRetry={retry}
                onDismiss={dismiss}
              />
            )}
          />
        )}

        {otherUserTyping ? (
          <View className="px-lg pb-xs">
            <TypingIndicator />
          </View>
        ) : null}

        <ChatComposer
          onSend={(text) => send(text, 'text')}
          onChangeText={notifyTyping}
          onStopTyping={notifyStopTyping}
        />
      </KeyboardAvoider>
    </Screen>
  );
}
