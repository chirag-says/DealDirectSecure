/**
 * User and session endpoints. Mounted at `/api/users` (backend/routes/userRoutes.js).
 *
 * Authentication is COOKIE-BASED. The session token is an opaque 48-byte random
 * string, not a JWT, and it is never present in any response body. There is no
 * token endpoint and no refresh endpoint, so no refresh flow exists to build.
 */

import type {
  AuthResponse,
  ChangePasswordRequest,
  ForgotPasswordRequest,
  LoginRequest,
  ProfileResponse,
  RegisterRequest,
  RegisterResponse,
  ResendOtpRequest,
  ResetPasswordRequest,
  SessionsResponse,
  VerifyOtpRequest,
} from '@/types/backend/user';
import type { ObjectId, OkEnvelope } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const usersEndpoints = {
  register: defineEndpoint<RegisterRequest, RegisterResponse>({
    method: 'POST',
    path: '/users/register',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Creates an UNVERIFIED user and sends an OTP by SMS. Body capped at 20KB. ' +
      'Does not establish a session; verify-otp does that. For owner registration only.',
  }),

  registerDirect: defineEndpoint<RegisterRequest, AuthResponse>({
    method: 'POST',
    path: '/users/register-direct',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Creates a VERIFIED buyer account and ESTABLISHES THE SESSION via Set-Cookie. ' +
      'No OTP required. For buyer (role: "user") registration only.',
  }),

  verifyOtp: defineEndpoint<VerifyOtpRequest, AuthResponse>({
    method: 'POST',
    path: '/users/verify-otp',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Returns 201 and ESTABLISHES THE SESSION via Set-Cookie. Do not follow this with a ' +
      'login call; the user is already authenticated.',
  }),

  resendOtp: defineEndpoint<ResendOtpRequest, OkEnvelope>({
    method: 'POST',
    path: '/users/resend-otp',
    auth: 'public',
    envelope: 'ok',
    rateLimit: 'auth',
  }),

  login: defineEndpoint<LoginRequest, AuthResponse>({
    method: 'POST',
    path: '/users/login',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Body capped at 10KB. Session arrives ONLY as Set-Cookie. Distinct failure codes: ' +
      '401 invalid credentials, 423 ACCOUNT_LOCKED (with lockoutUntil), 403 ACCOUNT_BLOCKED ' +
      '(with blockReason), 400 EMAIL_NOT_VERIFIED.',
  }),

  logout: defineEndpoint<void, OkEnvelope>({
    method: 'POST',
    path: '/users/logout',
    auth: 'user',
    envelope: 'ok',
  }),

  logoutAll: defineEndpoint<void, OkEnvelope>({
    method: 'POST',
    path: '/users/logout-all',
    auth: 'user',
    envelope: 'ok',
    note: 'Revokes every session for the user, including the calling device.',
  }),

  forgotPassword: defineEndpoint<ForgotPasswordRequest, OkEnvelope>({
    method: 'POST',
    path: '/users/forgot-password',
    auth: 'public',
    envelope: 'ok',
    rateLimit: 'auth',
    note:
      'Sends a 6-digit OTP to the user\'s phone via SMS. Body is `{ phone }` ' +
      '(email accepted as fallback). Returns 404 if no account matches. ' +
      'There is no email link and no token.',
  }),

  resetPassword: defineEndpoint<ResetPasswordRequest, OkEnvelope>({
    method: 'POST',
    path: '/users/reset-password',
    auth: 'public',
    envelope: 'ok',
    rateLimit: 'auth',
    note:
      'Verifies the SMS OTP and sets the new password. Full password-strength ' +
      'rules apply. Revokes all sessions on success. Body: `{ phone | email, otp, newPassword }`.',
  }),

  /** Alias of `/users/profile`. Used for the cold-start session probe. */
  me: defineEndpoint<void, ProfileResponse>({
    method: 'GET',
    path: '/users/me',
    auth: 'user',
    envelope: 'keyed',
    note: 'Returns 401 when unauthenticated, which is the expected probe result for a guest.',
  }),

  profile: defineEndpoint<void, ProfileResponse>({
    method: 'GET',
    path: '/users/profile',
    auth: 'user',
    envelope: 'keyed',
  }),

  updateProfile: defineEndpoint<FormData, ProfileResponse>({
    method: 'PUT',
    path: '/users/profile',
    auth: 'user',
    envelope: 'keyed',
    note: 'multipart/form-data. Optional single file field `profileImage`.',
  }),

  changePassword: defineEndpoint<ChangePasswordRequest, OkEnvelope>({
    method: 'PUT',
    path: '/users/change-password',
    auth: 'user',
    envelope: 'ok',
  }),

  deleteAccount: defineEndpoint<void, OkEnvelope>({
    method: 'DELETE',
    path: '/users/me',
    auth: 'user',
    envelope: 'ok',
    note: 'Required by App Store policy to be reachable in-app. Already implemented backend-side.',
  }),

  sessions: defineEndpoint<void, SessionsResponse>({
    method: 'GET',
    path: '/users/sessions',
    auth: 'user',
    envelope: 'keyed',
  }),

  revokeSession: defineEndpoint<void, OkEnvelope, { sessionId: ObjectId }>({
    method: 'DELETE',
    path: ({ sessionId }) => `/users/sessions/${sessionId}`,
    auth: 'user',
    envelope: 'ok',
  }),

  sendUpgradeOtp: defineEndpoint<void, OkEnvelope>({
    method: 'POST',
    path: '/users/send-upgrade-otp',
    auth: 'user',
    envelope: 'ok',
    note: 'Buyer to owner upgrade. Requires a VERIFIED account (requireVerified).',
  }),

  verifyUpgradeOtp: defineEndpoint<{ otp: string }, OkEnvelope>({
    method: 'POST',
    path: '/users/verify-upgrade-otp',
    auth: 'user',
    envelope: 'ok',
    note: 'On success the role becomes `owner`. Refetch the profile afterwards.',
  }),
} as const;
