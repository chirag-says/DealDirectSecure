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
 * NEITHER STATE CONFIRMS WHETHER THE PHONE EXISTS. Doing so would turn this
 * endpoint into an account-enumeration oracle — anyone could test whether a
 * given Indian mobile has a DealDirect account, ten digits at a time.
 *
 * That was true of the success state from the start and false of the error
 * state until 2026-08-16, which made the protection worthless: the 404 branch
 * printed the backend's "No account found with this phone number" verbatim.
 * A 404 now lands on the same "code sent" screen as a success. See the handler.
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
      /*
        THE 404 IS SWALLOWED, DELIBERATELY — fixed 2026-08-16.

        This handler used to print `error.message`, and the backend's message
        for an unknown number is "No account found with this phone number".
        That is an account-enumeration oracle: anyone can test whether a given
        Indian mobile has a DealDirect account, ten digits at a time.

        The docstring above this component already said the success state must
        not confirm whether the phone exists, and it was right — but the error
        path leaked exactly what the success path was protecting. Both branches
        now say the same thing, which is the only way the protection holds.

        Rate limiting is still surfaced, because a user who has to wait needs
        to know how long, and it reveals nothing about the account.
      */
      if (error instanceof ApiError && error.status === 404) {
        setSent(true);
        return;
      }

      if (error instanceof ApiError && error.kind === 'rateLimited') {
        const minutes = error.retryAfterSeconds
          ? Math.ceil(error.retryAfterSeconds / 60)
          : 15;
        setFormError(`Too many attempts. Try again in about ${minutes} minutes.`);
        return;
      }

      setFormError(
        error instanceof ApiError
          ? error.message
          : 'Something went wrong. Please try again.'
      );
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
