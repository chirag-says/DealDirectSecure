import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import React from 'react';
import { View } from 'react-native';

import { radius, useTheme } from '@/theme';
import { EmptyState, Screen, ScreenHeader } from '@/ui';
import { useAuth } from '../AuthProvider';
import { SignInPrompt } from './SignInPrompt';

/**
 * The gate on the six owner routes.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * `/owner/properties`, `/owner/leads`, `/owner/leads/[id]`,
 * `/owner/analytics`, `/owner/property/new` and `/owner/property/[id]/edit`
 * had no client-side role check at all. They rely on the API rejecting a
 * non-owner, which it does — but that turns an ACCESS decision into an ERROR
 * state: a buyer who deep-links `/owner/leads` gets a titled screen that
 * renders, spins, and then says "Could not load leads". The honest reading of
 * that screen is "something is broken", when in fact nothing is.
 *
 * Two different refusals, because they need two different ways out:
 *
 *   signed out       `SignInPrompt` — the existing pattern, with a route to
 *                    both sign-in and registration
 *   signed in, buyer `EmptyState` pointing at Profile, where the
 *                    buyer-to-owner upgrade sheet lives
 *
 * The second one matters more than it looks. "You need an owner account" with
 * no route to getting one is the dead end this whole codebase keeps correcting;
 * the upgrade exists, it is two taps away, and this is where a user finds out
 * it exists at all.
 *
 * ---------------------------------------------------------------------------
 * IT DOES NOT REPLACE THE SERVER CHECK AND MUST NOT BE READ AS SECURITY
 *
 * The client knows the role from `sanitizeUser`'s response, which the user
 * cannot forge into a working session but can trivially alter in a patched
 * build. Every one of these routes is still gated server-side and stays that
 * way. This is a usability control: it changes what a legitimate user is told,
 * not what an illegitimate one can reach.
 */
export interface OwnerOnlyProps {
  /** Shown on the refusal screens so the user still knows where they are. */
  title: string;
  /** Where the header's back control goes. Defaults to Profile. */
  backTo?: string;
  children: React.ReactNode;
}

export function OwnerOnly({ title, backTo = '/(tabs)/profile', children }: OwnerOnlyProps) {
  const router = useRouter();
  const theme = useTheme();
  const { status, user } = useAuth();

  // Session not restored yet. Rendering a refusal here would flash "sign in"
  // on every cold start for a user who is in fact a signed-in owner.
  if (status === 'restoring') return <>{children}</>;

  if (status !== 'authenticated' || !user) {
    return (
      <Screen>
        <ScreenHeader title={title} backTo={backTo} />
        <SignInPrompt
          icon="key-outline"
          title="Owner tools"
          description="Sign in with an owner account to post a listing and manage the enquiries it receives."
        />
      </Screen>
    );
  }

  if (user.role !== 'owner') {
    return (
      <Screen>
        <ScreenHeader title={title} backTo={backTo} />
        <EmptyState
          icon={
            <View
              className="items-center justify-center"
              style={{
                width: 72,
                height: 72,
                borderRadius: radius.full,
                backgroundColor: theme.colors.accentMuted,
              }}
            >
              <Ionicons name="key-outline" size={30} color={theme.colors.accent} />
            </View>
          }
          title="For owner accounts"
          description="Listing a property, and the leads and analytics that come with it, need an owner account. You can upgrade from your profile — it takes one verification code."
          actionLabel="Go to profile"
          actionVariant="primary"
          onAction={() => router.replace('/(tabs)/profile')}
        />
      </Screen>
    );
  }

  return <>{children}</>;
}
