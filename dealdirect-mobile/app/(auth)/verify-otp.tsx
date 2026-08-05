import { zodResolver } from '@hookform/resolvers/zod';
import { router, useLocalSearchParams } from 'expo-router';
import { useEffect, useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Alert, Pressable, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth, verifyOtpSchema, type VerifyOtpValues } from '@/auth';
import { Button, Input, KeyboardAvoider, Screen, Text } from '@/ui';

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
  const { email } = useLocalSearchParams<{ email?: string }>();
  const { verifyOtp, resendOtp } = useAuth();
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
      <Screen>
        <View className="flex-1 items-center justify-center px-xl">
          <Text variant="title3" className="text-center">
            Missing email address
          </Text>
          <Text variant="callout" tone="secondary" className="mt-sm text-center">
            Start again from registration to receive a code.
          </Text>
          <Button
            label="Back to login"
            className="mt-lg"
            onPress={() => router.replace('/(auth)/login')}
          />
        </View>
      </Screen>
    );
  }

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await verifyOtp(email, values.otp);
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
      Alert.alert('Code sent', `A new code is on its way to ${email}.`);
    } catch (error) {
      setFormError(
        error instanceof ApiError ? error.message : 'Could not resend the code.'
      );
    }
  };

  return (
    <Screen>
      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{ padding: 24, flexGrow: 1, justifyContent: 'center' }}
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="display">Enter the code</Text>
          <Text variant="callout" tone="secondary" className="mb-xl mt-sm">
            We sent a 6-digit code to {email}. It expires in 10 minutes.
          </Text>

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
            className="mt-base self-center"
          >
            <Text variant="callout" tone={cooldown > 0 ? 'muted' : 'accent'}>
              {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
            </Text>
          </Pressable>

          <Pressable
            onPress={() => router.replace('/(auth)/login')}
            className="mt-xl self-center"
          >
            <Text variant="footnote" tone="muted">
              Start over
            </Text>
          </Pressable>
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
