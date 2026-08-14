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
    revoke: useCallback((sessionId: string) => mutation.mutate(sessionId), [mutation]),
    pendingId: mutation.isPending ? (mutation.variables ?? null) : null,
    error: mutation.error,
  };
}

// --- Delete account ------------------------------------------------------

export function useDeleteAccount() {
  const { logout } = useAuth();

  const mutation = useMutation({
    mutationFn: () => call(usersEndpoints.deleteAccount),
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

// --- Buyer to owner upgrade ----------------------------------------------

/**
 * `requireVerified` gates both calls, so an unverified email is rejected by
 * the backend before an OTP is ever sent. That 400 surfaces through
 * `sendOtp`'s error like any other.
 */
export function useOwnerUpgrade() {
  const { refreshUser } = useAuth();
  const [otpSent, setOtpSent] = useState(false);

  const sendMutation = useMutation({
    mutationFn: () => call(usersEndpoints.sendUpgradeOtp),
    onSuccess: () => setOtpSent(true),
  });

  const verifyMutation = useMutation({
    mutationFn: (otp: string) => call(usersEndpoints.verifyUpgradeOtp, { data: { otp } }),
    onSuccess: () => refreshUser(),
  });

  return {
    otpSent,
    sendOtp: sendMutation.mutateAsync,
    isSending: sendMutation.isPending,
    sendError: sendMutation.error,
    verifyOtp: verifyMutation.mutateAsync,
    isVerifying: verifyMutation.isPending,
    verifyError: verifyMutation.error,
    reset: () => {
      setOtpSent(false);
      sendMutation.reset();
      verifyMutation.reset();
    },
  };
}
