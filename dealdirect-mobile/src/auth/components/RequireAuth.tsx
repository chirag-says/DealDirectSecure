import React from 'react';

import { Screen, ScreenHeader } from '@/ui';
import { useAuth } from '../AuthProvider';
import type { PendingIntent } from '../pendingIntent';
import { SignInPrompt } from './SignInPrompt';

/**
 * The gate on a route that needs an account but no particular role.
 *
 * `OwnerOnly` already does this for the six owner routes, but it also asserts a
 * role, which is wrong for account screens: changing your password or reviewing
 * your active devices is something every signed-in user does, buyer or owner.
 * This is the same shape with the role check removed.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE ROUTES NEEDED IT
 *
 * `settings/sessions`, `settings/change-password`, `settings/delete-account`
 * and `claim-reward/[verificationId]` rendered for a guest and failed at the
 * request. Every one is deep-linkable — the scheme covers the whole route tree,
 * and the reward screen is reached from a notification tap, which is precisely
 * the moment a session may have lapsed. What the user saw was a titled screen
 * that spun and then reported an error, for the ordinary condition of not being
 * signed in.
 *
 * `restoring` renders the children, matching `OwnerOnly`: showing a refusal
 * during the cold-start probe would flash "sign in" at a user who is signed in.
 * A screen behind this gate must therefore still tolerate a moment with no
 * user, which is what the query layer's `enabled` guards are for.
 *
 * ---------------------------------------------------------------------------
 * NOT SECURITY. Every route behind this is enforced server-side and stays that
 * way; the client knows the session state only from a response it cannot forge
 * into a working cookie but can trivially alter in a patched build. This
 * changes what a legitimate user is told, not what an illegitimate one reaches.
 */
export interface RequireAuthProps {
  /** Shown on the refusal screen so the user still knows where they are. */
  title: string;
  /** Names what is behind the gate, not the act of signing in. */
  promptTitle: string;
  promptDescription: string;
  icon?: React.ComponentProps<typeof SignInPrompt>['icon'];
  /** Where the header's back control goes. */
  backTo?: string;
  /** Passed to the prompt so signing in returns to what was interrupted. */
  intent?: PendingIntent;
  children: React.ReactNode;
}

export function RequireAuth({
  title,
  promptTitle,
  promptDescription,
  icon,
  backTo,
  intent,
  children,
}: RequireAuthProps) {
  const { status } = useAuth();

  if (status === 'restoring') return <>{children}</>;

  if (status !== 'authenticated') {
    return (
      <Screen>
        <ScreenHeader title={title} backTo={backTo} />
        <SignInPrompt
          icon={icon}
          title={promptTitle}
          description={promptDescription}
          intent={intent}
        />
      </Screen>
    );
  }

  return <>{children}</>;
}
