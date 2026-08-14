import { useRouter } from 'expo-router';
import { useCallback, useEffect } from 'react';
import { Alert, FlatList, RefreshControl, View } from 'react-native';

import {
  ConversationRow,
  useChatConversations,
  useDeleteConversation,
  type ConversationSummary,
} from '@/features/chat';
import { requestNotificationPermissionOnce } from '@/notifications';
import { tabBarClearance, useTheme } from '@/theme';
import { EmptyState, ErrorState, Screen, Skeleton, Text, useToast } from '@/ui';

/**
 * Messages.
 *
 * Not paginated — `GET /chat/conversations` returns every active conversation
 * in one call, sorted by `updatedAt`, so there is no "load more" here for the
 * same reason there is none on the notifications screen.
 */
export default function ChatListScreen() {
  const router = useRouter();
  const theme = useTheme();

  const { items, isLoading, isRefreshing, error, refresh, requiresAuth } = useChatConversations();
  const { remove } = useDeleteConversation();
  const toast = useToast();

  // Asked here, not at launch: a permission prompt only makes sense once the
  // user has shown intent to use messaging. Asks at most once ever — see
  // `requestNotificationPermissionOnce`'s doc comment.
  useEffect(() => {
    if (!requiresAuth) void requestNotificationPermissionOnce();
  }, [requiresAuth]);

  const openConversation = useCallback(
    (id: string) => router.push(`/chat/${id}`),
    [router]
  );

  const confirmArchive = useCallback(
    (conversation: ConversationSummary) => {
      Alert.alert(
        'Archive this conversation?',
        `You will stop seeing messages with ${conversation.otherParticipant?.name ?? 'this user'} about "${conversation.propertyTitle}". They can still message you again.`,
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Archive',
            style: 'destructive',
            onPress: async () => {
              await remove(conversation.id);
              toast.show('Conversation archived.');
            },
          },
        ]
      );
    },
    [remove]
  );

  return (
    <Screen>
      <View className="px-lg pt-md pb-sm">
        <Text variant="title1">Messages</Text>
      </View>

      {requiresAuth ? (
        <EmptyState
          title="Sign in to message owners"
          description="Conversations you start from a listing appear here."
          actionLabel="Sign in"
          onAction={() => router.push('/(auth)/login')}
        />
      ) : isLoading ? (
        <ChatListSkeleton />
      ) : error ? (
        <ErrorState title="Could not load your messages" onRetry={refresh} />
      ) : items.length === 0 ? (
        <EmptyState
          title="No conversations yet"
          description="Message an owner from any listing to start one."
          actionLabel="Browse listings"
          onAction={() => router.push('/(tabs)/properties')}
        />
      ) : (
        <FlatList
          data={items}
          keyExtractor={(item) => item.id}
          refreshControl={
            <RefreshControl
              refreshing={isRefreshing}
              onRefresh={refresh}
              tintColor={theme.colors.textMuted}
              colors={[theme.colors.accent]}
              progressBackgroundColor={theme.colors.surface}
            />
          }
          contentContainerStyle={{ paddingBottom: tabBarClearance }}
          renderItem={({ item }) => (
            <ConversationRow
              conversation={item}
              onPress={openConversation}
              onArchive={confirmArchive}
            />
          )}
        />
      )}
    </Screen>
  );
}

function ChatListSkeleton() {
  return (
    <View className="px-base pt-sm">
      {[0, 1, 2, 3, 4, 5].map((row) => (
        <View key={row} className="flex-row items-center py-md">
          <Skeleton width={44} height={44} radius={9999} />
          <View className="ml-md flex-1">
            <Skeleton width="50%" height={15} />
            <Skeleton width="70%" height={13} className="mt-xs" />
          </View>
        </View>
      ))}
    </View>
  );
}
