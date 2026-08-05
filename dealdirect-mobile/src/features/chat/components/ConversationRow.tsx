import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { useTheme } from '@/theme';
import { useIsParticipantOnline } from '../hooks';
import { Avatar, Badge, Image, Text } from '@/ui';
import type { ConversationSummary } from '../types';

/**
 * One row in the conversation list.
 *
 * The online dot reads `useIsParticipantOnline`, which is the GLOBAL presence
 * set the server broadcasts to every connected socket (see
 * `socket/types.ts`) — accurate, but not private the way a per-contact status
 * feature usually implies. That is a backend behaviour this row inherits
 * rather than one it introduces.
 */

/** "You: …" only on the current user's own last message, matching the
 *  website's list treatment so a preview reads as a preview, not a quote. */
function preview(conversation: ConversationSummary): string | undefined {
  if (!conversation.lastMessageText) return undefined;
  const prefix = conversation.lastMessageIsMine ? 'You: ' : '';
  return `${prefix}${conversation.lastMessageText}`;
}

function timeAgo(iso: string | undefined): string {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';

  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 60) return 'now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d`;
  return new Date(iso).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
}

export interface ConversationRowProps {
  conversation: ConversationSummary;
  onPress: (id: string) => void;
  /** Explicit action rather than a hidden long-press, matching this app's
   *  established pattern of a visible control for a destructive-ish action
   *  (see the "Remove" link on the saved-listings row). */
  onArchive: (conversation: ConversationSummary) => void;
}

function ConversationRowComponent({ conversation, onPress, onArchive }: ConversationRowProps) {
  const theme = useTheme();
  const online = useIsParticipantOnline(conversation.otherParticipant?.id);
  const handlePress = useCallback(() => onPress(conversation.id), [onPress, conversation.id]);
  const handleArchive = useCallback(() => onArchive(conversation), [onArchive, conversation]);
  const unread = conversation.unreadCount > 0;

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`Conversation with ${conversation.otherParticipant?.name ?? 'user'} about ${conversation.propertyTitle}`}
      onPress={handlePress}
      style={({ pressed }) => (pressed ? { opacity: 0.7 } : undefined)}
      className="flex-row items-center px-lg py-md"
    >
      <View>
        <Avatar
          uri={conversation.otherParticipant?.profileImage}
          name={conversation.otherParticipant?.name}
          size="md"
        />
        {online ? (
          <View className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-surface bg-success" />
        ) : null}
      </View>

      <View className="ml-md flex-1">
        <View className="flex-row items-center justify-between">
          <Text variant={unread ? 'bodyEmphasis' : 'body'} numberOfLines={1} className="flex-1">
            {conversation.otherParticipant?.name ?? 'Unknown user'}
          </Text>
          <Text variant="caption" tone="muted" className="ml-sm">
            {timeAgo(conversation.lastMessageAt ?? conversation.updatedAt)}
          </Text>
        </View>

        <Text variant="footnote" tone="secondary" numberOfLines={1} className="mt-xs">
          {conversation.propertyTitle}
        </Text>

        {preview(conversation) ? (
          <Text
            variant="footnote"
            tone={unread ? 'primary' : 'muted'}
            numberOfLines={1}
            className="mt-xs"
          >
            {preview(conversation)}
          </Text>
        ) : null}
      </View>

      {conversation.propertyImage ? (
        <Image
          uri={conversation.propertyImage}
          size="thumb"
          style={{ width: 44, height: 44, borderRadius: 8, marginLeft: 8 }}
        />
      ) : null}

      {unread ? (
        <View className="ml-sm">
          <Badge label={String(conversation.unreadCount)} tone="accent" />
        </View>
      ) : null}

      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Archive conversation with ${conversation.otherParticipant?.name ?? 'user'}`}
        onPress={handleArchive}
        hitSlop={8}
        className="ml-sm"
      >
        <Ionicons name="archive-outline" size={18} color={theme.colors.textMuted} />
      </Pressable>
    </Pressable>
  );
}

export const ConversationRow = memo(ConversationRowComponent);
