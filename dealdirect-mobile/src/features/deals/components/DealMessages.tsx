import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, View } from 'react-native';

import { track } from '@/analytics';
import { ApiError } from '@/api';
import {
  ChatComposer,
  MessageBubble,
  TypingIndicator,
  setActiveConversationId,
  useMessageThread,
  type ChatMessage,
} from '@/features/chat';
import { spacing, useTheme } from '@/theme';
import type { DealConversation } from '@/types/backend/deal';
import { Button, Card, Text } from '@/ui';
import { useOpenConversation } from '../hooks';
import { ReportMessageSheet } from './ReportMessageSheet';

/**
 * The message wall inside a deal.
 *
 * ---------------------------------------------------------------------------
 * A THREAD ON A PAGE, NOT A PAGE OF THREAD
 *
 * `app/chat/[conversationId].tsx` is a full-screen inverted FlatList. This
 * is the same thread (same hook, same bubbles, same composer) embedded in a
 * scrolling deal page, so it renders its messages as plain views: a
 * virtualised list inside a ScrollView fights it for the gesture and warns
 * on mount. A page is 50 messages, which is a cheap number of views; older
 * history is a "Load earlier" button at the top rather than an infinite
 * scroll the outer page would swallow.
 *
 * ---------------------------------------------------------------------------
 * THREE QUIET STATES AND ONE LIVE ONE
 *
 *   chatEnabled false     one muted line; the server has chat switched off
 *   conversation null     a button that opens one (`POST /deals/:id/conversation`)
 *   503 CHAT_DISABLED     the same muted line, if the switch flipped mid-session
 *   conversation present  the thread
 *
 * ---------------------------------------------------------------------------
 * SYSTEM WARNINGS AND REPORTING
 *
 * A message the server flagged is followed by a `system` message both
 * parties see. It is rendered here (not by `MessageBubble`) so it can carry
 * a warning icon and read as the platform speaking. Any message from the
 * other party can be long-pressed to report it; the action is also exposed
 * to assistive tech through `accessibilityActions`, since a long press is
 * not discoverable by a screen reader.
 */

export interface DealMessagesProps {
  leadId: string;
  conversation: DealConversation | null;
  chatEnabled: boolean;
  counterpartName: string;
  /** The composer took focus; the page scrolls it above the keyboard. */
  onComposerFocus?: () => void;
}

export function DealMessages({
  leadId,
  conversation,
  chatEnabled,
  counterpartName,
  onComposerFocus,
}: DealMessagesProps) {
  const { open, isPending, error, isDisabled } = useOpenConversation(leadId);

  if (!chatEnabled || isDisabled) {
    return (
      <Card>
        <Text variant="bodyEmphasis">Messages</Text>
        <Text variant="footnote" tone="muted" className="mt-xs">
          Messaging is not available yet.
        </Text>
      </Card>
    );
  }

  if (!conversation) {
    return (
      <Card>
        <Text variant="bodyEmphasis">Messages</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          Ask a question, share a document, agree a time. Everything stays on this deal.
        </Text>
        <View className="mt-base">
          <Button
            label="Start a conversation"
            size="sm"
            loading={isPending}
            onPress={() => open().catch(() => {})}
          />
        </View>
        {error && !(error instanceof ApiError && error.code === 'CHAT_DISABLED') ? (
          <Text variant="footnote" tone="danger" className="mt-sm">
            {error instanceof ApiError ? error.message : 'Could not start the conversation.'}
          </Text>
        ) : null}
      </Card>
    );
  }

  return (
    <Thread
      leadId={leadId}
      conversationId={conversation.id}
      counterpartName={counterpartName}
      onComposerFocus={onComposerFocus}
    />
  );
}

function Thread({
  leadId,
  conversationId,
  counterpartName,
  onComposerFocus,
}: {
  leadId: string;
  conversationId: string;
  counterpartName: string;
  onComposerFocus?: () => void;
}) {
  const theme = useTheme();
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

  const [reporting, setReporting] = useState<string | null>(null);

  // The push bridge (when mounted) suppresses a local notification for the
  // thread on screen. Cleared on unmount so leaving the deal resumes them.
  useEffect(() => {
    setActiveConversationId(conversationId);
    return () => setActiveConversationId(null);
  }, [conversationId]);

  const handleSend = useCallback(
    (text: string) => {
      send(text, 'text');
      track('message_sent', { leadId });
    },
    [send, leadId]
  );

  return (
    <Card padded={false}>
      <View className="px-base pt-base">
        <Text variant="bodyEmphasis">Messages</Text>
      </View>

      <View style={{ paddingVertical: spacing.sm, minHeight: 96 }}>
        {isLoading ? (
          <View className="items-center py-lg">
            <ActivityIndicator color={theme.colors.textMuted} />
          </View>
        ) : error && messages.length === 0 ? (
          <View className="items-center px-base py-md">
            <Text variant="footnote" tone="danger" className="text-center">
              Could not load messages.
            </Text>
            <Button label="Try again" variant="ghost" size="sm" onPress={refresh} />
          </View>
        ) : messages.length === 0 ? (
          <View className="items-center px-base py-md">
            <Text variant="footnote" tone="muted" className="text-center">
              No messages yet. Say hello to {counterpartName}.
            </Text>
          </View>
        ) : (
          <>
            {hasMore ? (
              <View className="items-center pb-sm">
                {isLoadingMore ? (
                  <ActivityIndicator size="small" color={theme.colors.textMuted} />
                ) : (
                  <Button label="Load earlier" variant="ghost" size="sm" onPress={loadMore} />
                )}
              </View>
            ) : null}
            {messages.map((message) => (
              <MessageRow
                key={message.id || message.clientId!}
                message={message}
                onRetry={retry}
                onDismiss={dismiss}
                onReport={setReporting}
              />
            ))}
          </>
        )}

        {otherUserTyping ? (
          <View className="px-lg pt-xs">
            <TypingIndicator />
          </View>
        ) : null}
      </View>

      <ChatComposer
        onSend={handleSend}
        onChangeText={notifyTyping}
        onStopTyping={notifyStopTyping}
        onFocus={onComposerFocus}
      />

      <ReportMessageSheet messageId={reporting} onClose={() => setReporting(null)} />
    </Card>
  );
}

function MessageRow({
  message,
  onRetry,
  onDismiss,
  onReport,
}: {
  message: ChatMessage;
  onRetry: (clientId: string) => void;
  onDismiss: (clientId: string) => void;
  onReport: (messageId: string) => void;
}) {
  const theme = useTheme();

  if (message.messageType === 'system') {
    return (
      <View className="my-sm items-center px-lg">
        <View
          className="flex-row items-start rounded-lg px-md py-sm"
          style={{ backgroundColor: theme.colors.warningMuted, maxWidth: '92%' }}
          accessible
          accessibilityLabel={`DealDirect warning: ${message.text}`}
        >
          <Ionicons
            name="warning-outline"
            size={14}
            color={theme.colors.warning}
            style={{ marginTop: 2 }}
          />
          <Text variant="caption" tone="secondary" className="ml-xs flex-1">
            {message.text}
          </Text>
        </View>
      </View>
    );
  }

  const bubble = (
    <MessageBubble
      message={message}
      isOwner={false}
      alreadyAccepted
      onRetry={onRetry}
      onDismiss={onDismiss}
    />
  );

  // Only the other party's messages can be reported; the server refuses
  // OWN_MESSAGE and there is nothing to gain from offering it.
  if (message.isMine || !message.id) return bubble;

  return (
    <Pressable
      onLongPress={() => onReport(message.id)}
      delayLongPress={400}
      accessible
      accessibilityLabel={`${message.senderName}: ${message.text}`}
      accessibilityHint="Long press to report this message"
      accessibilityActions={[{ name: 'longpress', label: 'Report message' }]}
      onAccessibilityAction={(event) => {
        if (event.nativeEvent.actionName === 'longpress') onReport(message.id);
      }}
    >
      {bubble}
    </Pressable>
  );
}
