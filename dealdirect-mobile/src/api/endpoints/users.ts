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
  DeleteAccountRequest,
  DeleteAccountResponse,
  ForgotPasswordRequest,
  GoogleLinkRequest,
  GoogleSignInRequest,
  LoginRequest,
  LogoutRequest,
  PhoneStatusResponse,
  ProfileResponse,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  RegisterPushTokenRequest,
  RegisterPushTokenResponse,
  RegisterRequest,
  RegisterResponse,
  RemovePushTokenRequest,
  RemovePushTokenResponse,
  ResendOtpRequest,
  ResetPasswordRequest,
  SendPhoneOtpRequest,
  SendPhoneOtpResponse,
  SessionsResponse,
  VerifyOtpRequest,
  VerifyPhoneOtpRequest,
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

  logout: defineEndpoint<LogoutRequest, OkEnvelope>({
    method: 'POST',
    path: '/users/logout',
    auth: 'user',
    envelope: 'ok',
    note:
      'Body is optional. `{ pushToken }` deletes that device token in the same request, ' +
      'so the phone stops receiving that account\'s push after sign-out.',
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

  deleteAccount: defineEndpoint<DeleteAccountRequest, DeleteAccountResponse>({
    method: 'DELETE',
    path: '/users/me',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Required by App Store policy to be reachable in-app. Takes a BODY on a DELETE: ' +
      '`{ password }` is mandatory (400 PASSWORD_REQUIRED without it, 401 INVALID_PASSWORD ' +
      'if wrong). Cascades across 12 collections; listings holding deal evidence are kept ' +
      'and counted back as `retainedListings`.',
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

  registerPushToken: defineEndpoint<RegisterPushTokenRequest, RegisterPushTokenResponse>({
    method: 'POST',
    path: '/users/push-token',
    auth: 'user',
    envelope: 'data',
    note:
      'Idempotent: the same token re-posted is re-pointed at the current account. ' +
      'Called only after the OS permission is already granted; see notifications/pushToken.ts.',
  }),

  removePushToken: defineEndpoint<RemovePushTokenRequest, RemovePushTokenResponse>({
    method: 'DELETE',
    path: '/users/push-token',
    auth: 'user',
    envelope: 'keyed',
    note: 'Takes a BODY on a DELETE: `{ token }`. `call()` sends `data` for every non-GET method.',
  }),

  registerDevice: defineEndpoint<RegisterDeviceRequest, RegisterDeviceResponse>({
    method: 'POST',
    path: '/users/device',
    auth: 'user',
    envelope: 'ok',
    note:
      'Opaque installation id, 16-128 url-safe chars. Fire-and-forget, once per authenticated ' +
      'session (see auth/deviceLink.ts). Feeds the close-deal fraud-linkage check; nothing else.',
  }),

  // --- Google sign-in ----------------------------------------------------

  googleSignIn: defineEndpoint<GoogleSignInRequest, AuthResponse>({
    method: 'POST',
    path: '/users/auth/google',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Takes Google\'s signed idToken and ESTABLISHES THE SESSION via Set-Cookie. ' +
      '201 for a new account, 200 for a returning one. ' +
      '409 GOOGLE_LINK_REQUIRED means the email already has a PASSWORD account and no ' +
      'session was issued — collect that password and call googleLink. That refusal is a ' +
      'step in the flow, not an error: the backend will not merge on an email match alone, ' +
      'because registration never verified email.',
  }),

  googleLink: defineEndpoint<GoogleLinkRequest, AuthResponse>({
    method: 'POST',
    path: '/users/auth/google/link',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'auth',
    note:
      'Second half of a 409 GOOGLE_LINK_REQUIRED. Attaches Google to the existing account ' +
      'and signs in. Shares the password-login lockout counter, so repeated wrong passwords ' +
      'return 423 ACCOUNT_LOCKED exactly as /users/login does.',
  }),

  // --- Just-in-time phone verification -----------------------------------

  sendPhoneOtp: defineEndpoint<SendPhoneOtpRequest, SendPhoneOtpResponse>({
    method: 'POST',
    path: '/users/phone/send-otp',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Sends a 6-digit SMS code to link a number to the signed-in account. ' +
      'Capped at 3 sends per 15 minutes PER ACCOUNT (429 OTP_SEND_LIMIT, with retryAfter) — ' +
      'a new IP does not buy more. 409 PHONE_ALREADY_LINKED if another account holds it. ' +
      'Returns alreadyVerified:true and sends nothing when it is already this account\'s number.',
  }),

  verifyPhoneOtp: defineEndpoint<VerifyPhoneOtpRequest, AuthResponse>({
    method: 'POST',
    path: '/users/phone/verify-otp',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Links the number and returns the updated user. Five wrong guesses BURN the code ' +
      '(400 OTP_INVALID carries attemptsRemaining; the sixth attempt is OTP_EXPIRED), so the ' +
      'UI must show the count rather than let the code appear to stop working.',
  }),

  phoneStatus: defineEndpoint<void, PhoneStatusResponse>({
    method: 'GET',
    path: '/users/phone/status',
    auth: 'user',
    envelope: 'keyed',
    note:
      'For a client resuming mid-flow — after the app was killed while the user read the SMS, ' +
      'which is the normal case, not the rare one.',
  }),

  // --- Legacy ------------------------------------------------------------
  //
  // Superseded by the phone gate: the role is now granted server-side on the
  // first listing attempt. Kept so published builds keep working.

  sendUpgradeOtp: defineEndpoint<void, OkEnvelope>({
    method: 'POST',
    path: '/users/send-upgrade-otp',
    auth: 'user',
    envelope: 'ok',
    note: 'LEGACY. Buyer to owner upgrade. Requires a VERIFIED account (requireVerified).',
  }),

  verifyUpgradeOtp: defineEndpoint<{ otp: string }, OkEnvelope>({
    method: 'POST',
    path: '/users/verify-upgrade-otp',
    auth: 'user',
    envelope: 'ok',
    note: 'LEGACY. On success the role becomes `owner`. Refetch the profile afterwards.',
  }),
} as const;
