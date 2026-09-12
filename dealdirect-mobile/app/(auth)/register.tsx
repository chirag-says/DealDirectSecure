import Ionicons from '@expo/vector-icons/Ionicons';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link } from 'expo-router';
import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import {
  AuthShell,
  GoogleAuthButton,
  GoogleLinkSheet,
  isGoogleSignInConfigured,
  registerSchema,
  resumeAfterAuth,
  useAuth,
  type RegisterValues,
} from '@/auth';
import { gesture, useTheme } from '@/theme';
import { Button, Input, Text } from '@/ui';

/**
 * Registration. One form, for everyone.
 *
 * ---------------------------------------------------------------------------
 * WHAT USED TO BE HERE, AND WHY IT IS GONE
 *
 * This screen used to open with "I want to: Buy or rent / List a property",
 * and that choice decided everything after it. "List a property" sent the user
 * through an SMS OTP before the account existed; "Buy or rent" did not.
 *
 * Two problems. The choice was asked at the worst possible moment — before
 * anyone has seen a single listing, they are made to declare which kind of
 * person they are — and it was wrong as often as not, since most owners browse
 * before they list. And the OTP was a toll gate on a stranger who had not yet
 * been given a reason to spend one.
 *
 * So neither is asked here now. The account is created immediately, and both
 * facts are established later at the moment they actually matter:
 *
 *   - the ROLE is granted server-side the first time the account lists a
 *     property (middleware/requirePhoneVerified.js, `ensureOwnerRole`)
 *   - the PHONE is verified just in time, by a sheet the API layer raises when
 *     a gated action is refused (src/auth/phoneGate.ts)
 *
 * The phone field is gone from this form entirely. Collecting a number here
 * and verifying it later would mean asking for the same thing twice.
 */
export default function RegisterScreen() {
  const { registerDirect } = useAuth();
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingLink, setPendingLink] = useState<{ email: string; idToken: string } | null>(null);
  const theme = useTheme();
  const [showPassword, setShowPassword] = useState(false);

  const { control, handleSubmit, formState, getValues } = useForm<RegisterValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      name: '',
      email: '',
      password: '',
      referralCode: '',
    },
  });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);

    try {
      await registerDirect({
        ...values,
        referralCode: values.referralCode?.trim() || undefined,
      });
      resumeAfterAuth();
    } catch (error) {
      if (!(error instanceof ApiError)) {
        setFormError('Something went wrong. Please try again.');
        return;
      }

      if (error.kind === 'rateLimited') {
        setFormError('Too many attempts. Please wait a few minutes and try again.');
        return;
      }

      // An email that already belongs to a Google account cannot take a
      // password here. Point at the door that works rather than at the error.
      if (error.code === 'USE_GOOGLE_SIGNIN') {
        setFormError('This email already signs in with Google. Use Continue with Google above.');
        return;
      }

      // The backend names an email or phone that is already registered. Pass
      // that through: it is more specific than anything written here.
      setFormError(error.message);
    }
  });

  return (
    <AuthShell
      title="Create account"
      subtitle="Takes a minute. No verification code needed."
      // The longest form in the app: the short photograph, so the first
      // field is on screen before any scrolling.
      band="compact"
      footer={
        <View className="flex-row items-center justify-center">
          <Text variant="callout" tone="secondary">
            Already have an account?{' '}
          </Text>
          <Link href="/(auth)/login" asChild>
            <Pressable hitSlop={gesture.hitSlop}>
              <Text variant="bodyEmphasis" tone="accent">
                Log in
              </Text>
            </Pressable>
          </Link>
        </View>
      }
    >
      <GoogleAuthButton
        referralCode={getValues('referralCode')?.trim() || undefined}
        onLinkRequired={(email, idToken) => setPendingLink({ email, idToken })}
        onSignedIn={resumeAfterAuth}
      />

      {/* The divider belongs to the Google button: with no button above it, an
          "or" announces an alternative that is not there. */}
      {isGoogleSignInConfigured() ? (
        <View className="mb-base flex-row items-center gap-sm">
          <View className="h-px flex-1 bg-border" />
          <Text variant="footnote" tone="muted">
            or sign up with email
          </Text>
          <View className="h-px flex-1 bg-border" />
        </View>
      ) : null}

      <Controller
        control={control}
        name="name"
        render={({ field, fieldState }) => (
          <Input
            label="Full name"
            placeholder="Your name"
            leading={<Ionicons name="person-outline" size={18} color={theme.colors.textMuted} />}
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
            leading={<Ionicons name="mail-outline" size={18} color={theme.colors.textMuted} />}
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
            placeholder="Choose a password"
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
            leading={<Ionicons name="gift-outline" size={18} color={theme.colors.textMuted} />}
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
