import { useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { GoogleSignInCancelled, RequireAuth, signInWithGoogle, useAuth } from '@/auth';
import { confirmWithBiometrics } from '@/native';
import { useDeleteAccount } from '@/features/profile';
import { Button, Input, Screen, ScreenHeader, Text, useToast } from '@/ui';

const CONFIRM_WORD = 'DELETE';

export default function DeleteAccountRoute() {
  return (
    <RequireAuth
      title="Delete account"
      promptTitle="Delete your account"
      promptDescription="Sign in to the account you want to delete. Deletion is permanent and has to be re-confirmed."
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
 * against a mis-tap; re-authentication is the actual authorisation, re-checked
 * server-side before anything is deleted. The website asks for the phrase
 * `DELETE-<email>`; that is a keyboard-sized decision, not a security one, and a
 * bare word is the right version of it on a phone.
 *
 * WHICH proof is asked for depends on the account. A Google account has no
 * password, so it re-confirms through Google instead — the backend requires
 * that token's `sub` to match this account's own. Showing a password field to
 * someone who has never had a password would be an unpassable wall in front of
 * the one screen App Store review insists must work.
 */
function DeleteAccountScreen() {
  const router = useRouter();
  const toast = useToast();
  const { user } = useAuth();
  const { deleteAccount, isPending, error } = useDeleteAccount();
  const [confirmText, setConfirmText] = useState('');
  const [password, setPassword] = useState('');
  const [googleError, setGoogleError] = useState<string | null>(null);

  // Absent `authMethods` means the profile read did not report them, NOT that
  // the account has no password. Defaulting to the password path keeps the
  // long-standing behaviour for every account that predates this field.
  const usesGoogleOnly = user?.authMethods
    ? !user.authMethods.password && user.authMethods.google
    : false;

  const wordTyped = confirmText.trim().toUpperCase() === CONFIRM_WORD;
  const canDelete = wordTyped && (usesGoogleOnly || password.length > 0);

  const handleDelete = async () => {
    if (!canDelete) return;

    /*
      A physical confirm before the point of no return.

      The typed phrase guards a mis-tap and the password is the real
      authorisation — the server still requires it and re-checks it. This adds
      a fingerprint on top: proof the phone is in its owner's hands before it
      deletes their account. On a device with no biometric this returns true
      and the flow proceeds on the password alone, because a confirmation the
      device cannot perform must not become a wall. See `native/biometrics`.
    */
    const confirmed = await confirmWithBiometrics('Confirm you want to delete your account');
    if (!confirmed) return;

    setGoogleError(null);

    try {
      // A Google account proves itself by passing Google's challenge again,
      // right now. That is what a stale session cannot do, and it is the same
      // standard the password path holds to.
      let proof: { password: string } | { idToken: string };
      if (usesGoogleOnly) {
        try {
          proof = { idToken: await signInWithGoogle() };
        } catch (err) {
          if (err instanceof GoogleSignInCancelled) return;
          setGoogleError('Could not confirm with Google. Your account was not deleted.');
          return;
        }
      } else {
        proof = { password };
      }

      const response = await deleteAccount(proof);

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

        {usesGoogleOnly ? (
          <Text variant="footnote" tone="secondary" className="mt-base">
            You will be asked to confirm with Google before anything is deleted.
          </Text>
        ) : (
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
        )}

        {googleError ? (
          <Text variant="footnote" tone="danger" className="mt-base">
            {googleError}
          </Text>
        ) : null}

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
