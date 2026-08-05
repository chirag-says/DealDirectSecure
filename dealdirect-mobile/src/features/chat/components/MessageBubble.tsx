import Ionicons from '@expo/vector-icons/Ionicons';
import { ActivityIndicator, Pressable, View } from 'react-native';

import { useTheme } from '@/theme';
import { Text } from '@/ui';
import type { ChatMessage } from '../types';

/**
 * One message.
 *
 * ---------------------------------------------------------------------------
 * WHY visit_request AND visit_confirmation LOOK NOTHING LIKE A CHAT BUBBLE
 *
 * The website renders every `messageType` through one component and the same
 * left/right coloured bubble; a visit request is only distinguishable by an
 * "Accept Visit" button appearing under otherwise ordinary-looking text. The
 * architecture plan asks for these to render as distinct bubble types on
 * mobile, and a centred card with an icon is what makes that true rather than
 * nominal: it reads as a SCHEDULING EVENT the thread is tracking, not as
 * something either participant said.
 *
 * ---------------------------------------------------------------------------
 * THE ACCEPT BUTTON TRACKS STATE THE WEBSITE DOES NOT
 *
 * The website's accept control is gated only on `Boolean(isOwner)` — it has no
 * memory of whether a given request was already accepted, so it keeps
 * offering "Accept Visit" on the same message forever. `alreadyAccepted` is
 * computed by the thread screen (any `visit_confirmation` later in the same
 * conversation counts as handling every prior request) and hides the button
 * once one exists, which is a small, backend-free correctness improvement
 * over the reference behaviour rather than a port of it.
 */

export interface MessageBubbleProps {
  message: ChatMessage;
  /** Only an owner can accept a visit request directed at them. */
  isOwner: boolean;
  /** Hides the Accept action once a later `visit_confirmation` exists. */
  alreadyAccepted: boolean;
  onAccept?: (message: ChatMessage) => void;
  onRetry?: (clientId: string) => void;
  onDismiss?: (clientId: string) => void;
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
}

export function MessageBubble({
  message,
  isOwner,
  alreadyAccepted,
  onAccept,
  onRetry,
  onDismiss,
}: MessageBubbleProps) {
  const theme = useTheme();

  if (message.messageType === 'system') {
    return (
      <View className="my-sm items-center">
        <Text variant="caption" tone="muted" className="text-center">
          {message.text}
        </Text>
      </View>
    );
  }

  if (message.messageType === 'visit_request' || message.messageType === 'visit_confirmation') {
    const isConfirmation = message.messageType === 'visit_confirmation';
    const canAccept = !isConfirmation && isOwner && !message.isMine && !alreadyAccepted;

    return (
      <View className="my-sm items-center px-lg">
        <View
          className={`w-full max-w-[85%] rounded-2xl border px-md py-sm ${
            isConfirmation ? 'border-success bg-success-muted' : 'border-accent bg-accent-muted'
          }`}
        >
          <View className="flex-row items-center">
            <Ionicons
              name={isConfirmation ? 'checkmark-circle-outline' : 'calendar-outline'}
              size={16}
              color={isConfirmation ? theme.colors.success : theme.colors.accent}
            />
            <Text
              variant="caption"
              tone={isConfirmation ? 'success' : 'accent'}
              className="ml-xs"
              style={{ fontWeight: '600' }}
            >
              {isConfirmation ? 'Visit confirmed' : 'Site visit requested'}
            </Text>
          </View>

          <Text variant="footnote" className="mt-xs">
            {message.text}
          </Text>

          {canAccept ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Accept visit request"
              onPress={() => onAccept?.(message)}
              className="mt-sm self-start rounded-full bg-success px-md py-xs"
              style={({ pressed }) => (pressed ? { opacity: 0.75 } : undefined)}
            >
              <Text variant="caption" className="text-white" style={{ fontWeight: '600' }}>
                Accept visit
              </Text>
            </Pressable>
          ) : null}

          <Text variant="caption" tone="muted" className="mt-xs">
            {formatTime(message.createdAt)}
          </Text>
        </View>
      </View>
    );
  }

  if (message.messageType === 'image' || message.messageType === 'file') {
    // No path exists anywhere in this backend to upload a chat attachment —
    // `sendMessage` only ever writes a `text` field. These types are modelled
    // because the schema allows them, not because they are reachable from any
    // client today. Rendered honestly rather than assuming a shape of data
    // (a URL, a filename) that nothing populates.
    return (
      <View className={`my-xs px-lg ${message.isMine ? 'items-end' : 'items-start'}`}>
        <View className="max-w-[80%] rounded-2xl bg-surface-muted px-md py-sm">
          <Text variant="footnote" tone="muted" style={{ fontStyle: 'italic' }}>
            Unsupported message type
          </Text>
        </View>
      </View>
    );
  }

  return (
    <View className={`my-xs px-lg ${message.isMine ? 'items-end' : 'items-start'}`}>
      <View
        className={`max-w-[80%] rounded-2xl px-md py-sm ${
          message.isMine ? 'rounded-br-md bg-accent' : 'rounded-bl-md bg-surface-muted'
        }`}
      >
        <Text
          variant="body"
          className={message.isMine ? 'text-white' : undefined}
          style={{ lineHeight: 20 }}
        >
          {message.text}
        </Text>

        <View className="mt-xs flex-row items-center justify-end">
          {message.status === 'sending' ? (
            <ActivityIndicator
              size="small"
              color={message.isMine ? '#ffffff' : theme.colors.textMuted}
            />
          ) : (
            <Text
              variant="caption"
              className={message.isMine ? 'text-white/70' : undefined}
              tone={message.isMine ? undefined : 'muted'}
            >
              {formatTime(message.createdAt)}
            </Text>
          )}
        </View>
      </View>

      {message.status === 'failed' ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Retry sending this message"
          onPress={() => message.clientId && onRetry?.(message.clientId)}
          className="mt-xs flex-row items-center"
        >
          <Ionicons name="alert-circle" size={13} color={theme.colors.danger} />
          <Text variant="caption" tone="danger" className="ml-xs">
            Failed to send · Tap to retry
          </Text>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Discard this message"
            hitSlop={8}
            onPress={() => message.clientId && onDismiss?.(message.clientId)}
            className="ml-sm"
          >
            <Ionicons name="close" size={13} color={theme.colors.textMuted} />
          </Pressable>
        </Pressable>
      ) : null}
    </View>
  );
}
