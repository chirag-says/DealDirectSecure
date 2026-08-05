import { zodResolver } from '@hookform/resolvers/zod';
import { Link, router } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Pressable, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { registerSchema, useAuth, type RegisterValues } from '@/auth';
import { Button, Chip, Input, KeyboardAvoider, Screen, Text } from '@/ui';

/**
 * Registration.
 *
 * Creates an UNVERIFIED account and sends a 6-digit OTP. It does not establish
 * a session; `verify-otp` does that, and going straight there afterwards is
 * the whole flow.
 *
 * The role choice is offered up front because it changes what the account can
 * do: `owner` unlocks listing creation, leads and agreements. Choosing "buyer"
 * is not a dead end, since the buyer-to-owner upgrade exists behind an OTP,
 * but making the choice visible here avoids a surprise later.
 *
 * The backend rejects anything that is not the literal string "owner" down to
 * "user", so only those two values are ever sent.
 *
 * Password rules mirror the backend exactly (see auth/schemas.ts) and are shown
 * as a hint rather than only on failure, because a rule the user cannot see is
 * a rule they will break.
 */
export default function RegisterScreen() {
  const { register } = useAuth();
  const [formError, setFormError] = useState<string | null>(null);

  const { control, handleSubmit, formState, watch, setValue, getValues } =
    useForm<RegisterValues>({
      resolver: zodResolver(registerSchema),
      defaultValues: {
        name: '',
        email: '',
        phone: '',
        password: '',
        role: 'user',
        referralCode: '',
      },
    });

  const role = watch('role');

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);

    try {
      await register({
        ...values,
        referralCode: values.referralCode?.trim() || undefined,
      });

      router.push({
        pathname: '/(auth)/verify-otp',
        params: { email: getValues('email') },
      });
    } catch (error) {
      if (!(error instanceof ApiError)) {
        setFormError('Something went wrong. Please try again.');
        return;
      }

      if (error.kind === 'rateLimited') {
        setFormError('Too many attempts. Please wait a few minutes and try again.');
        return;
      }

      // The backend returns a specific 400 for an email or phone that already
      // belongs to a verified account, and it names which one. Pass it through.
      setFormError(error.message);
    }
  });

  return (
    <Screen>
      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{ padding: 24, flexGrow: 1 }}
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="display" className="mt-xl">
            Create account
          </Text>
          <Text variant="callout" tone="secondary" className="mb-xl mt-sm">
            You will receive a 6-digit code to verify your number.
          </Text>

          <Text variant="subhead" tone="secondary" className="mb-sm">
            I want to
          </Text>
          <View className="mb-lg flex-row gap-sm">
            <Chip
              label="Buy or rent"
              selected={role === 'user'}
              onPress={() => setValue('role', 'user')}
            />
            <Chip
              label="List a property"
              selected={role === 'owner'}
              onPress={() => setValue('role', 'owner')}
            />
          </View>

          <Controller
            control={control}
            name="name"
            render={({ field, fieldState }) => (
              <Input
                label="Full name"
                placeholder="Your name"
                autoComplete="name"
                textContentType="name"
                value={field.value}
                onChangeText={field.onChange}
                onBlur={field.onBlur}
                error={fieldState.error?.message}
              />
            )}
          />

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
            name="phone"
            render={({ field, fieldState }) => (
              <Input
                label="Mobile number"
                placeholder="10-digit number"
                keyboardType="number-pad"
                maxLength={10}
                autoComplete="tel"
                textContentType="telephoneNumber"
                value={field.value}
                onChangeText={field.onChange}
                onBlur={field.onBlur}
                error={fieldState.error?.message}
                hint="The verification code is sent here"
              />
            )}
          />

          <Controller
            control={control}
            name="password"
            render={({ field, fieldState }) => (
              <Input
                label="Password"
                placeholder="Choose a password"
                secureTextEntry
                autoCapitalize="none"
                autoComplete="new-password"
                textContentType="newPassword"
                value={field.value}
                onChangeText={field.onChange}
                onBlur={field.onBlur}
                error={fieldState.error?.message}
                hint="At least 8 characters, with upper and lower case, a number and a symbol"
              />
            )}
          />

          <Controller
            control={control}
            name="referralCode"
            render={({ field, fieldState }) => (
              <Input
                label="Referral code (optional)"
                placeholder="Enter a code if you have one"
                autoCapitalize="characters"
                value={field.value ?? ''}
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
            label="Create account"
            fullWidth
            loading={formState.isSubmitting}
            onPress={() => void onSubmit()}
          />

          <View className="mt-xl flex-row items-center justify-center">
            <Text variant="callout" tone="secondary">
              Already have an account?{' '}
            </Text>
            <Link href="/(auth)/login" asChild>
              <Pressable>
                <Text variant="bodyEmphasis" tone="accent">
                  Log in
                </Text>
              </Pressable>
            </Link>
          </View>
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
