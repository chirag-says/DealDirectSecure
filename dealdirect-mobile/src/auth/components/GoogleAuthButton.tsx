import Ionicons from '@expo/vector-icons/Ionicons';
import { useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { useTheme } from '@/theme';
import { Button, Text } from '@/ui';
import { useAuth, type GoogleSignInOutcome } from '../AuthProvider';
import {
  GoogleSignInCancelled,
  GoogleSignInUnavailable,
  isGoogleSignInConfigured,
} from '../googleSignIn';

export interface GoogleAuthButtonProps {
  /** Carried through a first-time sign-in so referral attribution is not lost. */
  referralCode?: string;
  /** Called when the account already has a password and must be proved first. */
  onLinkRequired: (email: string, idToken: string) => void;
  /** Called after a session is established. */
  onSignedIn: () => void;
}

/**
 * "Continue with Google", on both the login and register screens.
 *
 * Renders NOTHING when the build has no Google client ID. A button that always
 * fails is worse than no button: it reads as a broken app rather than as a
 * feature that is not switched on, and it would be the first thing every user
 * tried. This is also what lets the app ship before the OAuth credentials
 * exist.
 *
 * Cancellation is silent. The user closing the Google sheet is them saying no,
 * not an error, and an error line under a button they deliberately dismissed is
 * the app arguing with them.
 */
export function GoogleAuthButton({
  referralCode,
  onLinkRequired,
  onSignedIn,
}: GoogleAuthButtonProps) {
  const { signInWithGoogle } = useAuth();
  const theme = useTheme();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isGoogleSignInConfigured()) return null;

  const onPress = async () => {
    setError(null);
    setBusy(true);
    try {
      const outcome: GoogleSignInOutcome = await signInWithGoogle(referralCode);

      if (outcome.status === 'linkRequired') {
        onLinkRequired(outcome.email, outcome.idToken);
        return;
      }

      onSignedIn();
    } catch (err) {
      if (err instanceof GoogleSignInCancelled) return;

      if (err instanceof GoogleSignInUnavailable) {
        setError(err.message);
        return;
      }

      if (err instanceof ApiError) {
        if (err.code === 'ACCOUNT_BLOCKED') {
          setError(
            err.details.blockReason
              ? `Your account has been blocked: ${err.details.blockReason}`
              : 'Your account has been blocked. Please contact support.'
          );
          return;
        }
        if (err.code === 'GOOGLE_EMAIL_NOT_VERIFIED') {
          setError(
            'That Google account has no verified email address. Sign in with email and password instead.'
          );
          return;
        }
        if (err.code === 'GOOGLE_NOT_CONFIGURED') {
          setError('Google sign-in is unavailable right now. Please use email and password.');
          return;
        }
        setError(err.message);
        return;
      }

      setError('Could not sign in with Google. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <View className="mb-base">
      <Button
        label="Continue with Google"
        variant="secondary"
        fullWidth
        loading={busy}
        /*
          Ionicons' monochrome glyph rather than Google's multi-colour "G".
          The project has no SVG renderer installed, and adding one for one
          16-pixel mark is not a trade worth making. If brand review ever
          matters, the options are `GoogleSigninButton` from the SDK (official
          asset, its own fixed styling, which will not match this button) or
          react-native-svg with the supplied mark.
        */
        leading={<Ionicons name="logo-google" size={18} color={theme.colors.textPrimary} />}
        onPress={() => void onPress()}
      />
      {error ? (
        <Text variant="footnote" tone="danger" className="mt-sm">
          {error}
        </Text>
      ) : null}
    </View>
  );
}
