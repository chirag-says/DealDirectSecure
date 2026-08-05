import { zodResolver } from '@hookform/resolvers/zod';
import { router } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { ScrollView, View } from 'react-native';

import { ApiError, call, usersEndpoints } from '@/api';
import { forgotPasswordSchema, type ForgotPasswordValues } from '@/auth';
import { Button, Input, KeyboardAvoider, Screen, Text } from '@/ui';

/**
 * Password reset request.
 *
 * The reset itself happens on the WEBSITE. The backend emails a link to a web
 * URL, and the token never reaches the app, so there is no in-app reset form to
 * build. The app's job is to trigger the email and set the expectation that the
 * next step is in their inbox.
 *
 * Revisit in M12 only if the website adds an app-scheme fallback carrying the
 * token; that is a website change, not a backend one.
 *
 * The success state deliberately does not confirm whether the address exists.
 * Doing so would turn this endpoint into an account-enumeration oracle.
 */
export default function ForgotPasswordScreen() {
  const [formError, setFormError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const { control, handleSubmit, formState, getValues } = useForm<ForgotPasswordValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: '' },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await call(usersEndpoints.forgotPassword, { data: values });
      setSent(true);
    } catch (error) {
      if (error instanceof ApiError && error.kind === 'rateLimited') {
        setFormError('Too many requests. Please wait a few minutes and try again.');
        return;
      }
      setFormError(
        error instanceof ApiError ? error.message : 'Something went wrong. Please try again.'
      );
    }
  });

  if (sent) {
    return (
      <Screen>
        <View className="flex-1 items-center justify-center px-xl">
          <Text variant="title2" className="text-center">
            Check your email
          </Text>
          <Text variant="callout" tone="secondary" className="mt-sm text-center">
            If an account exists for {getValues('email')}, we have sent a reset link. Open it
            in your browser to choose a new password, then come back and log in.
          </Text>
          <Button
            label="Back to login"
            className="mt-xl"
            onPress={() => router.replace('/(auth)/login')}
          />
        </View>
      </Screen>
    );
  }

  return (
    <Screen>
      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{ padding: 24, flexGrow: 1, justifyContent: 'center' }}
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="display">Reset password</Text>
          <Text variant="callout" tone="secondary" className="mb-xl mt-sm">
            Enter your email and we will send you a reset link.
          </Text>

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
                autoFocus
                value={field.value}
                onChangeText={field.onChange}
                onBlur={field.onBlur}
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
            label="Send reset link"
            fullWidth
            loading={formState.isSubmitting}
            onPress={() => void onSubmit()}
          />

          <Button
            label="Back to login"
            variant="ghost"
            fullWidth
            className="mt-sm"
            onPress={() => router.back()}
          />
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
