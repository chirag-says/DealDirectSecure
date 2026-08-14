import { zodResolver } from '@hookform/resolvers/zod';
import { router } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';

import { ApiError, call, usersEndpoints } from '@/api';
import {
  AuthResult,
  AuthShell,
  forgotPasswordSchema,
  normalizeIndianMobile,
  type ForgotPasswordValues,
} from '@/auth';
import { Button, Input, Text } from '@/ui';

/**
 * Password reset request.
 *
 * The backend sends a 6-digit OTP to the user's phone via SMS.
 * There is no email link and no token. The app collects the phone
 * number, triggers the SMS, and then routes to the in-app reset screen.
 *
 * The success state does not confirm whether the phone exists.
 * Doing so would turn this endpoint into an account-enumeration oracle.
 */
export default function ForgotPasswordScreen() {
  const [formError, setFormError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const { control, handleSubmit, formState, getValues } = useForm<ForgotPasswordValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { phone: '' },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await call(usersEndpoints.forgotPassword, { data: values });
      setSent(true);
    } catch (error) {
      if (error instanceof ApiError) {
        // Backend returns 404 with "No account found with this phone number"
        // — show it rather than hiding behind a generic message.
        setFormError(error.message);
      } else {
        setFormError('Something went wrong. Please try again.');
      }
    }
  });

  if (sent) {
    return (
      <AuthResult
        tone="info"
        title="Code sent"
        description={`We sent a 6-digit code by SMS to ${getValues('phone')}. Enter it on the next screen along with your new password.`}
        actionLabel="Continue"
        onAction={() =>
          router.replace({
            pathname: '/(auth)/reset-password',
            params: { phone: getValues('phone') },
          })
        }
      />
    );
  }

  return (
    <AuthShell
      title="Reset password"
      subtitle="Enter your phone number and we will send you a verification code by SMS."
      showBack
    >
      <Controller
        control={control}
        name="phone"
        render={({ field, fieldState }) => (
          <Input
            label="Mobile number"
            prefix="+91"
            placeholder="9876543210"
            keyboardType="number-pad"
            maxLength={10}
            autoComplete="tel"
            textContentType="telephoneNumber"
            value={field.value}
            onChangeText={(text) => field.onChange(normalizeIndianMobile(text))}
            onBlur={field.onBlur}
            error={fieldState.error?.message}
            hint="The number on your account"
          />
        )}
      />

      {formError ? (
        <Text variant="footnote" tone="danger" className="mb-md">
          {formError}
        </Text>
      ) : null}

      <Button
        label="Send code"
        fullWidth
        loading={formState.isSubmitting}
        onPress={() => void onSubmit()}
      />
    </AuthShell>
  );
}
