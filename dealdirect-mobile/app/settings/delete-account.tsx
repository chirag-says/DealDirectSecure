import { useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { useDeleteAccount } from '@/features/profile';
import { Button, Input, Screen, ScreenHeader, Text } from '@/ui';

const CONFIRM_WORD = 'DELETE';

/**
 * Account deletion. Reachable in-app because App Store review requires it, not
 * because it is a common path — hence the typed confirmation rather than a
 * single tap.
 */
export default function DeleteAccountScreen() {
  const router = useRouter();
  const { deleteAccount, isPending, error } = useDeleteAccount();
  const [confirmText, setConfirmText] = useState('');

  const canDelete = confirmText.trim().toUpperCase() === CONFIRM_WORD;

  const handleDelete = async () => {
    if (!canDelete) return;
    try {
      await deleteAccount();
      router.replace('/(auth)/login');
    } catch {
      // surfaced via `error` below
    }
  };

  return (
    <Screen>
      <ScreenHeader title="Delete account" />

      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <View className="mb-lg rounded-lg bg-danger-muted p-md">
          <Text variant="bodyEmphasis" tone="danger">
            This cannot be undone
          </Text>
          <Text variant="footnote" className="mt-xs">
            Your profile, listings, saved properties, conversations and reward balance are
            permanently removed. Any leads you have generated for owners are not affected.
          </Text>
        </View>

        <Text variant="body" className="mb-base">
          Type <Text variant="bodyEmphasis">{CONFIRM_WORD}</Text> to confirm.
        </Text>
        <Input
          value={confirmText}
          onChangeText={setConfirmText}
          autoCapitalize="characters"
          autoCorrect={false}
          placeholder={CONFIRM_WORD}
        />

        {error instanceof ApiError ? (
          <Text variant="footnote" tone="danger" className="mt-base">
            {error.message}
          </Text>
        ) : null}

        <Button
          label="Permanently delete my account"
          variant="danger"
          className="mt-xl"
          disabled={!canDelete}
          loading={isPending}
          onPress={() => void handleDelete()}
        />
      </ScrollView>
    </Screen>
  );
}
