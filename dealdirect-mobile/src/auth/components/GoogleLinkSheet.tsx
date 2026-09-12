import { useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { Button, Input, Sheet, Text } from '@/ui';
import { useAuth } from '../AuthProvider';

export interface GoogleLinkSheetProps {
  /** Null when closed. Otherwise the pending link, carried from the 409. */
  pending: { email: string; idToken: string } | null;
  onClose: () => void;
  onLinked: () => void;
}

/**
 * "This email already has an account. Enter its password to connect Google."
 *
 * ---------------------------------------------------------------------------
 * WHY THE USER IS ASKED FOR A PASSWORD AT ALL
 *
 * It would be friendlier to merge the two silently. Google verified the email,
 * so the person owns the inbox, so it must be them.
 *
 * Except that registration in this product has never verified email — neither
 * `registerUser` nor `registerUserDirect` checks that the person signing up can
 * read the address they typed. So an account under your Gmail can have been
 * created by anyone. Merging on an email match would drop the real owner
 * straight into a stranger's account: an account whose password the stranger
 * still knows, and whose contents they could then read at leisure, with nothing
 * visible happening to anyone.
 *
 * One password entry, once, ever. Five seconds for the real owner, and
 * impossible for someone who is not them.
 */
export function GoogleLinkSheet({ pending, onClose, onLinked }: GoogleLinkSheetProps) {
  const { linkGoogleAccount } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const close = () => {
    setPassword('');
    setError(null);
    onClose();
  };

  const onSubmit = async () => {
    if (!pending) return;
    if (!password) {
      setError('Enter your password.');
      return;
    }

    setError(null);
    setBusy(true);
    try {
      await linkGoogleAccount(pending.idToken, password);
      setPassword('');
      onLinked();
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.code === 'ACCOUNT_LOCKED') {
          // This endpoint shares the password-login lockout counter, so a
          // series of wrong guesses locks the account exactly as it would on
          // the login screen. Say how long rather than repeating "wrong".
          const minutes = err.details.lockoutUntil
            ? Math.max(
                1,
                Math.ceil((new Date(err.details.lockoutUntil).getTime() - Date.now()) / 60000)
              )
            : 15;
          setError(`Too many attempts. Try again in about ${minutes} minutes.`);
          return;
        }
        if (err.code === 'GOOGLE_ALREADY_LINKED') {
          setError('This account is already connected to a different Google account.');
          return;
        }
        setError(err.message);
        return;
      }
      setError('Could not connect Google. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet
      visible={pending !== null}
      onClose={close}
      title="Connect Google to your account"
      heightRatio={0.55}
    >
      <View className="gap-sm">
        <Text variant="callout" tone="secondary">
          {pending?.email
            ? `${pending.email} already has a DealDirect account. Enter its password once and Google will be connected to it.`
            : 'This email already has a DealDirect account. Enter its password once and Google will be connected to it.'}
        </Text>

        <Input
          label="Password"
          placeholder="Your existing password"
          secureTextEntry
          autoCapitalize="none"
          autoComplete="current-password"
          textContentType="password"
          returnKeyType="go"
          value={password}
          onChangeText={setPassword}
          onSubmitEditing={() => void onSubmit()}
          error={error ?? undefined}
        />

        <Button
          label="Connect and sign in"
          fullWidth
          loading={busy}
          onPress={() => void onSubmit()}
        />

        <Text variant="footnote" tone="muted" className="pt-sm">
          You will only be asked this once. After connecting, either sign-in method works.
        </Text>
      </View>
    </Sheet>
  );
}
