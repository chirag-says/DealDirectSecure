import { useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { RequireAuth } from '@/auth';
import { useDeleteAccount } from '@/features/profile';
import { Button, Input, Screen, ScreenHeader, Text, useToast } from '@/ui';

const CONFIRM_WORD = 'DELETE';

export default function DeleteAccountRoute() {
  return (
    <RequireAuth
      title="Delete account"
      promptTitle="Delete your account"
      promptDescription="Sign in to the account you want to delete. Deletion is permanent and needs your password."
      icon="trash-outline"
      backTo="/settings"
    >
      <DeleteAccountScreen />
    </RequireAuth>
  );
}

/**
 * Account deletion. Reachable in-app because App Store review requires it, not
 * because it is a common path — hence the typed confirmation rather than a
 * single tap.
 *
 * Two confirmations, doing different jobs. The typed word is a speed bump
 * against a mis-tap; the password is the actual authorisation, re-checked
 * server-side against the hash before anything is deleted. The website asks for
 * the phrase `DELETE-<email>`; that is a keyboard-sized decision, not a security
 * one, and a bare word is the right version of it on a phone.
 */
function DeleteAccountScreen() {
  const router = useRouter();
  const toast = useToast();
  const { deleteAccount, isPending, error } = useDeleteAccount();
  const [confirmText, setConfirmText] = useState('');
  const [password, setPassword] = useState('');

  const canDelete =
    confirmText.trim().toUpperCase() === CONFIRM_WORD && password.length > 0;

  const handleDelete = async () => {
    if (!canDelete) return;
    try {
      const response = await deleteAccount(password);

      // The success message promises the listings are gone. When the cascade
      // kept some back as deal evidence, say so instead of letting the promise
      // stand — this is the sentence a data-protection request is measured
      // against.
      toast.show(
        response.retainedListings
          ? `Account deleted. ${response.retainedListings} listing${
              response.retainedListings === 1 ? '' : 's'
            } tied to a live deal were kept on record.`
          : 'Your account has been deleted.'
      );
      router.replace('/(auth)/login');
    } catch {
      // surfaced via `error` below
    }
  };

  const wrongPassword = error instanceof ApiError && error.code === 'INVALID_PASSWORD';

  return (
    <Screen>
      <ScreenHeader title="Delete account" backTo="/settings" />

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

        <Input
          label="Your password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          autoCapitalize="none"
          autoComplete="current-password"
          textContentType="password"
          containerClassName="mt-base"
          error={wrongPassword ? 'That password is not correct.' : undefined}
        />

        {error instanceof ApiError && !wrongPassword ? (
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
