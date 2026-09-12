import Ionicons from '@expo/vector-icons/Ionicons';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link, router } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import {
  AuthShell,
  GoogleAuthButton,
  GoogleLinkSheet,
  isGoogleSignInConfigured,
  loginSchema,
  resumeAfterAuth,
  useAuth,
  type LoginValues,
} from '@/auth';
import { gesture, useTheme } from '@/theme';
import { Button, Input, Text } from '@/ui';

/**
 * Login.
 *
 * The backend distinguishes four failure modes here and each needs different
 * wording, so they are handled by `code` rather than collapsed into one
 * "login failed":
 *
 *   401 invalid credentials
 *   423 ACCOUNT_LOCKED      temporary, carries lockoutUntil
 *   403 ACCOUNT_BLOCKED     carries blockReason, which the user must be shown
 *   400 EMAIL_NOT_VERIFIED  recoverable, so route to OTP instead of dead-ending
 *
 * Login also sits behind the auth limiter at five attempts per 15 minutes.
 * Successful logins are not counted, but someone guessing their own password
 * can exhaust it, so a 429 says how long to wait rather than just failing.
 */
export default function LoginScreen() {
  const { login, endedReason, clearEndedReason } = useAuth();
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingLink, setPendingLink] = useState<{ email: string; idToken: string } | null>(null);
  const theme = useTheme();
  const [showPassword, setShowPassword] = useState(false);

  const { control, handleSubmit, formState, getValues } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    clearEndedReason();

    try {
      await login(values);
      resumeAfterAuth();
    } catch (error) {
      if (!(error instanceof ApiError)) {
        setFormError('Something went wrong. Please try again.');
        return;
      }

      if (error.code === 'EMAIL_NOT_VERIFIED') {
        router.push({
          pathname: '/(auth)/verify-otp',
          params: { email: getValues('email') },
        });
        return;
      }

      // The account exists but has no password: it was created with Google.
      // Naming the door that works beats "invalid email or password", which
      // would leave someone certain their account had vanished.
      if (error.code === 'USE_GOOGLE_SIGNIN') {
        setFormError('This account signs in with Google. Use Continue with Google above.');
        return;
      }

      if (error.code === 'ACCOUNT_BLOCKED') {
        setFormError(
          error.details.blockReason
            ? `Your account has been blocked: ${error.details.blockReason}`
            : 'Your account has been blocked. Please contact support.'
        );
        return;
      }

      if (error.kind === 'rateLimited') {
        const minutes = error.retryAfterSeconds ? Math.ceil(error.retryAfterSeconds / 60) : 15;
        setFormError(`Too many attempts. Try again in about ${minutes} minutes.`);
        return;
      }

      setFormError(error.message);
    }
  });

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Log in to pick up your enquiries, shortlist and listings."
      footer={
        <View className="flex-row items-center justify-center">
          <Text variant="callout" tone="secondary">
            New to DealDirect?{' '}
          </Text>
          <Link href="/(auth)/register" asChild>
            <Pressable hitSlop={gesture.hitSlop}>
              <Text variant="bodyEmphasis" tone="accent">
                Create an account
              </Text>
            </Pressable>
          </Link>
        </View>
      }
    >
      {endedReason ? (
        <View className="mb-base rounded-lg bg-warning-muted p-md">
          <Text variant="footnote">{endedReason}</Text>
        </View>
      ) : null}

      <GoogleAuthButton
        onLinkRequired={(email, idToken) => setPendingLink({ email, idToken })}
        onSignedIn={resumeAfterAuth}
      />

      {/* The divider belongs to the Google button: with no button above it, an
          "or" announces an alternative that is not there. */}
      {isGoogleSignInConfigured() ? (
        <View className="mb-base flex-row items-center gap-sm">
          <View className="h-px flex-1 bg-border" />
          <Text variant="footnote" tone="muted">
            or log in with email
          </Text>
          <View className="h-px flex-1 bg-border" />
        </View>
      ) : null}

      <Controller
        control={control}
        name="email"
        render={({ field, fieldState }) => (
          <Input
            label="Email"
            placeholder="you@example.com"
            leading={<Ionicons name="mail-outline" size={18} color={theme.colors.textMuted} />}
            autoCapitalize="none"
            autoComplete="email"
            keyboardType="email-address"
            textContentType="emailAddress"
            returnKeyType="next"
            value={field.value}
            onChangeText={field.onChange}
            onBlur={field.onBlur}
            error={fieldState.error?.message}
          />
        )}
      />

      <Controller
        control={control}
        name="password"
        render={({ field, fieldState }) => (
          <Input
            label="Password"
            placeholder="Your password"
            leading={<Ionicons name="lock-closed-outline" size={18} color={theme.colors.textMuted} />}
            /* Show/hide, because a password typed on a phone keyboard is
               mistyped often enough that seeing it is the fix, and the
               field is the one place a user cannot check what they wrote. */
            trailing={
              <Pressable
                accessibilityRole="button"
                accessibilityLabel={showPassword ? 'Hide password' : 'Show password'}
                hitSlop={gesture.hitSlop}
                onPress={() => setShowPassword((v) => !v)}
              >
                <Ionicons
                  name={showPassword ? 'eye-off-outline' : 'eye-outline'}
                  size={20}
                  color={theme.colors.textMuted}
                />
              </Pressable>
            }
            secureTextEntry={!showPassword}
            autoCapitalize="none"
            autoComplete="current-password"
            textContentType="password"
            returnKeyType="go"
            value={field.value}
            onChangeText={field.onChange}
            onBlur={field.onBlur}
            onSubmitEditing={() => void onSubmit()}
            error={fieldState.error?.message}
          />
        )}
      />

      {formError ? (
        <Text variant="footnote" tone="danger" className="mb-md">
          {formError}
        </Text>
      ) : null}

      <Button
        label="Log in"
        fullWidth
        loading={formState.isSubmitting}
        onPress={() => void onSubmit()}
      />

      <Link href="/(auth)/forgot-password" asChild>
        <Pressable className="mt-base self-center" hitSlop={gesture.hitSlop}>
          <Text variant="callout" tone="accent">
            Forgot password?
          </Text>
        </Pressable>
      </Link>

      {/* A way out that is not a dead end. Login is reached from gated
          actions as often as from the welcome screen, and a user who decides
          not to sign in should be able to keep browsing from here. */}
      <View className="mt-xl flex-row items-center" style={{ gap: 12 }}>
        <View className="h-px flex-1 bg-border" />
        <Text variant="caption" tone="muted">
          or
        </Text>
        <View className="h-px flex-1 bg-border" />
      </View>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Continue browsing without an account"
        className="mt-base self-center"
        hitSlop={gesture.hitSlop}
        onPress={() => router.replace('/(tabs)')}
      >
        <Text variant="callout" tone="secondary">
          Continue browsing as a guest
        </Text>
      </Pressable>

      <GoogleLinkSheet
        pending={pendingLink}
        onClose={() => setPendingLink(null)}
        onLinked={() => {
          setPendingLink(null);
          resumeAfterAuth();
        }}
      />
    </AuthShell>
  );
}
