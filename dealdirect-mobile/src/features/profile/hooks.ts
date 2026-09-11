/**
 * Account management: profile edit, password, sessions, deletion and the
 * buyer-to-owner upgrade.
 *
 * There is no `useProfile` query here. `AuthProvider` already holds the
 * current user from its cold-start `GET /users/me` probe, and every mutation
 * below calls `refreshUser()` on success rather than maintaining a second,
 * parallel cache of the same document.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useState } from 'react';

import { call, qk, usersEndpoints } from '@/api';
import { useAuth } from '@/auth';
import type { UserAddress, UserGender, UserSessionSummary } from '@/types/backend/user';

// --- Edit profile ----------------------------------------------------------

export interface UpdateProfileValues {
  name: string;
  phone?: string;
  alternatePhone?: string;
  address?: UserAddress;
  /** `YYYY-MM-DD`. `userController.js:943` only sets the field when truthy, so
   *  an already-set date of birth cannot be cleared through this endpoint —
   *  a backend limitation, not something to route around here. */
  dateOfBirth?: string;
  gender?: UserGender;
  bio?: string;
  emailNotifications?: boolean;
  smsNotifications?: boolean;
  /** A picked local image, not yet uploaded. Omit to leave the photo unchanged. */
  imageUri?: string;
}

function buildProfileFormData(values: UpdateProfileValues): FormData {
  const form = new FormData();
  form.append('name', values.name);
  if (values.phone) form.append('phone', values.phone);
  if (values.alternatePhone !== undefined) form.append('alternatePhone', values.alternatePhone);
  if (values.address !== undefined) form.append('address', JSON.stringify(values.address));
  if (values.dateOfBirth) form.append('dateOfBirth', values.dateOfBirth);
  if (values.gender !== undefined) form.append('gender', values.gender);
  if (values.bio !== undefined) form.append('bio', values.bio);
  if (values.emailNotifications !== undefined || values.smsNotifications !== undefined) {
    form.append(
      'preferences',
      JSON.stringify({
        emailNotifications: values.emailNotifications,
        smsNotifications: values.smsNotifications,
      })
    );
  }

  if (values.imageUri) {
    const filename = values.imageUri.split('/').pop() ?? 'profile.jpg';
    const ext = filename.split('.').pop()?.toLowerCase();
    const mime = ext === 'png' ? 'image/png' : ext === 'webp' ? 'image/webp' : 'image/jpeg';
    // React Native's FormData accepts this {uri,name,type} shape in place of a
    // real Blob; the DOM lib typing does not know that, hence the cast.
    form.append(
      'profileImage',
      { uri: values.imageUri, name: filename, type: mime } as unknown as Blob
    );
  }

  return form;
}

export function useUpdateProfile() {
  const { refreshUser } = useAuth();

  const mutation = useMutation({
    mutationFn: (values: UpdateProfileValues) =>
      call(usersEndpoints.updateProfile, { data: buildProfileFormData(values) }),
    onSuccess: () => refreshUser(),
  });

  return {
    update: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

// --- Change password ---------------------------------------------------

export function useChangePassword() {
  const mutation = useMutation({
    mutationFn: (values: { currentPassword: string; newPassword: string }) =>
      call(usersEndpoints.changePassword, { data: values }),
  });

  return {
    changePassword: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    reset: mutation.reset,
  };
}

// --- Active sessions ---------------------------------------------------

export function useSessions() {
  const query = useQuery({
    queryKey: qk.sessions,
    queryFn: async () => {
      const response = await call(usersEndpoints.sessions);
      return response.sessions;
    },
    staleTime: 30_000,
  });

  return {
    sessions: query.data ?? ([] as UserSessionSummary[]),
    isLoading: query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

export function useRevokeSession() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (sessionId: string) =>
      call(usersEndpoints.revokeSession, { params: { sessionId } }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.sessions }),
  });

  return {
    /*
      `mutateAsync`, NOT `mutate`.

      `mutate` returns void and never rejects, so the screen's
      `await revoke(id)` resolved on the same tick whatever happened and its
      success toast fired unconditionally — telling the user a device had been
      signed out when the request had failed and the session was still live.
      On a security screen that is the worst possible lie. Awaiting a real
      promise is what lets the caller tell the two outcomes apart.
    */
    revoke: useCallback((sessionId: string) => mutation.mutateAsync(sessionId), [mutation]),
    pendingId: mutation.isPending ? (mutation.variables ?? null) : null,
    error: mutation.error,
  };
}

// --- Delete account ------------------------------------------------------

/**
 * Permanent account deletion.
 *
 * Re-authentication is not optional and never was: `deleteAccount` refuses an
 * unproven body and re-checks the proof before touching any data. This once
 * sent no body at all, so every deletion attempt came back 400
 * `PASSWORD_REQUIRED` — the one flow App Store review is guaranteed to exercise.
 *
 * There are now two kinds of proof, because there are two kinds of account. A
 * password account sends its password. A Google account has none, so it sends a
 * freshly minted Google ID token instead, which the backend requires to match
 * that account's own `googleId`. Accepting only a password would have made
 * Google accounts undeletable — the same App Store failure, wearing a new hat.
 */
export function useDeleteAccount() {
  const { logout } = useAuth();

  const mutation = useMutation({
    mutationFn: (proof: { password: string } | { idToken: string }) =>
      call(usersEndpoints.deleteAccount, { data: proof }),
    // The account no longer exists server-side once this resolves, so the
    // local session is torn down the same way a normal logout would.
    onSuccess: () => logout(),
  });

  return {
    deleteAccount: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

// --- Buyer to owner upgrade: REMOVED -------------------------------------
//
// `useOwnerUpgrade` drove a "Become an owner" sheet that ran its own OTP against
// `/users/send-upgrade-otp`. Both are superseded: the role is granted
// server-side by `ensureOwnerRole` when an account first posts a listing, and
// the phone is verified by the just-in-time gate.
//
// It was also broken for the accounts this release creates. It texted
// `user.phone`, which a Google account does not have until the gate collects
// one, and gated its own button on `isVerified`, which a Google account has set
// to true. So the button was enabled and the send failed.
//
// The backend routes stay live for published builds that still call them.
