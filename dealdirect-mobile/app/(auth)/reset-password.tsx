import { zodResolver } from '@hookform/resolvers/zod';
import { router, useLocalSearchParams } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';

import { ApiError, call, usersEndpoints } from '@/api';
import { AuthResult, AuthShell, resetPasswordSchema, type ResetPasswordValues } from '@/auth';
import { Button, Input, Text } from '@/ui';

/**
 * Reset password — in-app screen.
 *
 * Receives the phone number from the forgot-password screen, collects the
 * SMS OTP and a new password, and posts to `POST /users/reset-password`.
 * The backend verifies the OTP, applies full password-strength rules, and
 * revokes every session on success.
 */
export default function ResetPasswordScreen() {
  const { phone } = useLocalSearchParams<{ phone?: string }>();
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const { control, handleSubmit, formState } = useForm<ResetPasswordValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { phone: phone ?? '', otp: '', newPassword: '', confirmPassword: '' },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await call(usersEndpoints.resetPassword, {
        data: { phone: values.phone, otp: values.otp, newPassword: values.newPassword },
      });
      setSuccess(true);
    } catch (error) {
      if (error instanceof ApiError) {
        setFormError(error.message);
      } else {
        setFormError('Something went wrong. Please try again.');
      }
    }
  });

  if (success) {
    return (
      <AuthResult
        tone="success"
        title="Password updated"
        description="Every device signed into this account has been signed out. Log in again with your new password."
        actionLabel="Go to login"
        onAction={() => router.replace('/(auth)/login')}
      />
    );
  }

  // Reached by deep link, or after a reload that lost the route param. There is
  // nothing to verify the OTP against, so the only honest move is to restart
  // the flow rather than show a form that cannot succeed.
  if (!phone) {
    return (
      <AuthResult
        tone="warning"
        title="Start again"
        description="We do not have a phone number for this reset. Request a new code to continue."
        actionLabel="Request new code"
        onAction={() => router.replace('/(auth)/forgot-password')}
      />
    );
  }

  return (
    <AuthShell
      title="Set new password"
      subtitle={`Enter the code we sent to ${phone} and choose a new password.`}
      showBack
      backTo="/(auth)/forgot-password"
      // Three fields plus two hints is tall enough to scroll on a small phone,
      // and centring would push the title off the top of the scroll view.
      center={false}
    >
      <Controller
        control={control}
        name="otp"
        render={({ field, fieldState }) => (
          <Input
            label="Verification code"
            placeholder="6-digit code"
            keyboardType="number-pad"
            maxLength={6}
            autoComplete="one-time-code"
            textContentType="oneTimeCode"
            autoFocus
            value={field.value}
            onChangeText={field.onChange}
            onBlur={field.onBlur}
            error={fieldState.error?.message}
          />
        )}
      />

      <Controller
        control={control}
        name="newPassword"
        render={({ field, fieldState }) => (
          <Input
            label="New password"
            placeholder="At least 8 characters"
            secureTextEntry
            autoCapitalize="none"
            autoComplete="new-password"
            textContentType="newPassword"
            value={field.value}
            onChangeText={field.onChange}
            onBlur={field.onBlur}
            error={fieldState.error?.message}
            hint="At least 8 characters, upper + lower case, a number and a symbol"
            containerClassName="mt-base"
          />
        )}
      />

      <Controller
        control={control}
        name="confirmPassword"
        render={({ field, fieldState }) => (
          <Input
            label="Confirm new password"
            placeholder="Re-enter your password"
            secureTextEntry
            autoCapitalize="none"
            autoComplete="new-password"
            textContentType="newPassword"
            value={field.value}
            onChangeText={field.onChange}
            onBlur={field.onBlur}
            error={fieldState.error?.message}
          />
        )}
      />

      {formError ? (
        <Text variant="footnote" tone="danger" className="mb-md mt-base">
          {formError}
        </Text>
      ) : null}

      <Button
        label="Update password"
        fullWidth
        loading={formState.isSubmitting}
        onPress={() => void onSubmit()}
        className="mt-base"
      />
    </AuthShell>
  );
}
