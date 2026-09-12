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
  /**
   * Let a signed-in NON-owner through.
   *
   * For the one route that is how an account becomes an owner: the create
   * listing form. Since the auth unification the role is no longer applied for
   * — `ensureOwnerRole` grants it server-side the moment an account first posts
   * a listing, behind the phone check. So refusing a buyer here would refuse
   * them the only door into the role, and the refusal screen's own "List a
   * property" action would loop straight back to itself.
   *
   * Everything else under /owner (leads, analytics, the listing list, the edit
   * form) genuinely needs an account that already owns something, and stays
   * refused.
   */
  allowNewOwners?: boolean;
  children: React.ReactNode;
}

export function OwnerOnly({
  title,
  backTo = '/(tabs)/profile',
  allowNewOwners = false,
  children,
}: OwnerOnlyProps) {
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

  if (user.role !== 'owner' && !allowNewOwners) {
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
          title="Post your first listing"
          description="Leads and analytics appear here once you have a property listed. Posting one is what turns this into an owner account — you will be asked to verify your mobile number along the way."
          actionLabel="List a property"
          actionVariant="primary"
          // Points at the listing form, not at Profile.
          //
          // The old copy sent people to a "become an owner" upgrade sheet, which
          // was the truth when the role was something you applied for. It is not
          // any more: `ensureOwnerRole` grants it server-side at the moment an
          // account first posts a listing. Sending someone to Profile now would
          // send them to look for a button that no longer needs to exist.
          onAction={() => router.push('/owner/property/new')}
        />
      </Screen>
    );
  }

  return <>{children}</>;
}
