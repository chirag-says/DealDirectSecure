import { zodResolver } from '@hookform/resolvers/zod';
import { Link, router } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import { AuthShell, loginSchema, useAuth, type LoginValues } from '@/auth';
import { gesture } from '@/theme';
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

  const { control, handleSubmit, formState, getValues } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    clearEndedReason();

    try {
      await login(values);
      router.replace('/(tabs)');
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
      subtitle="Log in to manage your listings and leads."
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

      <Controller
        control={control}
        name="email"
        render={({ field, fieldState }) => (
          <Input
            label="Email"
            placeholder="you@example.com"
            autoCapitalize="none"
            autoComplete="email"
            keyboardType="email-address"
            textContentType="emailAddress"
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
            secureTextEntry
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
    </AuthShell>
  );
}
