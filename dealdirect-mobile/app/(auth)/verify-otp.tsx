import { zodResolver } from '@hookform/resolvers/zod';
import { router, useLocalSearchParams } from 'expo-router';
import { useEffect, useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Pressable } from 'react-native';

import { ApiError } from '@/api';
import { AuthResult, AuthShell, useAuth, verifyOtpSchema, type VerifyOtpValues } from '@/auth';
import { gesture } from '@/theme';
import { Button, Input, Text, useToast } from '@/ui';

/** Backend OTP lifetime is 10 minutes; resend is offered well before that. */
const RESEND_COOLDOWN_SECONDS = 45;

/**
 * OTP verification.
 *
 * This is the step that ESTABLISHES the session: it returns 201 with a
 * Set-Cookie. Calling login afterwards would be redundant and would spend one
 * of the five attempts on the auth limiter.
 *
 * Back navigation is disabled on this route (see the group layout). Leaving
 * halfway strands a created-but-unverified account, and the user would then hit
 * "email is already registered" if they tried to register again. The explicit
 * "start over" action routes to login, from which registration is reachable
 * cleanly.
 */
export default function VerifyOtpScreen() {
  const { email, phone, referralCode } = useLocalSearchParams<{
    email?: string;
    phone?: string;
    referralCode?: string;
  }>();
  const { verifyOtp, resendOtp } = useAuth();
  const toast = useToast();
  const [formError, setFormError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(RESEND_COOLDOWN_SECONDS);

  const { control, handleSubmit, formState } = useForm<VerifyOtpValues>({
    resolver: zodResolver(verifyOtpSchema),
    defaultValues: { otp: '' },
  });

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((value) => value - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Reaching this screen without an email means the flow was entered wrongly;
  // there is nothing to verify against, so send the user back rather than
  // letting them type a code that can never succeed.
  if (!email) {
    return (
      <AuthResult
        tone="warning"
        title="Missing details"
        description="There is no account to verify against. Start again from registration to receive a code."
        actionLabel="Back to login"
        onAction={() => router.replace('/(auth)/login')}
      />
    );
  }

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await verifyOtp(email, values.otp, referralCode);
      router.replace('/(tabs)');
    } catch (error) {
      setFormError(
        error instanceof ApiError ? error.message : 'Something went wrong. Please try again.'
      );
    }
  });

  const onResend = async () => {
    setFormError(null);
    try {
      await resendOtp(email);
      setCooldown(RESEND_COOLDOWN_SECONDS);
      // A toast, not an Alert. The user asked for a code and got one; making
      // them dismiss a modal to confirm that is work for no information.
      toast.show(`New code sent to ${phone ?? email}.`, 'success');
    } catch (error) {
      setFormError(
        error instanceof ApiError ? error.message : 'Could not resend the code.'
      );
    }
  };

  return (
    /*
      No back affordance, deliberately. Leaving this screen strands a
      created-but-unverified account, and the user then hits "email already
      registered" on retry. `gestureEnabled: false` in the group layout blocks
      the swipe for the same reason; "Start over" below is the explicit exit
      that resets the flow properly.
    */
    <AuthShell
      title="Enter the code"
      subtitle={`We sent a 6-digit code by SMS to ${phone ?? email}. It expires in 10 minutes.`}
      footer={
        <Pressable
          onPress={() => router.replace('/(auth)/login')}
          hitSlop={gesture.hitSlop}
          className="self-center"
        >
          <Text variant="footnote" tone="muted">
            Start over
          </Text>
        </Pressable>
      }
    >
      <Controller
        control={control}
        name="otp"
        render={({ field, fieldState }) => (
          <Input
            label="Verification code"
            placeholder="123456"
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

      {formError ? (
        <Text variant="footnote" tone="danger" className="mb-md">
          {formError}
        </Text>
      ) : null}

      <Button
        label="Verify"
        fullWidth
        loading={formState.isSubmitting}
        onPress={() => void onSubmit()}
      />

      <Pressable
        disabled={cooldown > 0}
        onPress={() => void onResend()}
        hitSlop={gesture.hitSlop}
        className="mt-base self-center"
      >
        <Text variant="callout" tone={cooldown > 0 ? 'muted' : 'accent'}>
          {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
        </Text>
      </Pressable>
    </AuthShell>
  );
}
