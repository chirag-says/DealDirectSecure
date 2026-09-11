/**
 * User contract. Source: backend/models/userModel.js,
 * backend/controllers/userController.js, backend/middleware/authUser.js.
 */

import type { IsoDate, ObjectId, Timestamps } from './common';

/**
 * Role values.
 *
 * The schema defaults new users to `buyer`, `registerUser` normalises the
 * submitted role to either `owner` or `user`, and `sanitizeUser` in
 * middleware/authUser.js accepts exactly `user | buyer | owner` and THROWS for
 * anything else. So all three values occur in live data.
 *
 * Consequence for the app: `buyer` and `user` both mean "not an owner", but
 * they are not interchangeable everywhere. The agreement routes require
 * `owner | user` via `requireUserRole`, so an account whose role is literally
 * `buyer` is rejected there. See src/api/endpoints/agreements.ts.
 */
export type UserRole = 'user' | 'buyer' | 'owner';

/** `address` on the user document — home address, not a property's. */
export interface UserAddress {
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  pincode?: string;
}

export type UserGender = 'Male' | 'Female' | 'Other' | '';

/** The sanitised user object returned by login, register and profile reads. */
export interface User extends Timestamps {
  _id: ObjectId;
  name: string;
  email: string;
  phone?: string;
  alternatePhone?: string;
  address?: UserAddress;
  dateOfBirth?: IsoDate;
  gender?: UserGender;
  role: UserRole;
  profileImage?: string;
  bio?: string;
  /**
   * "This account is usable" — nothing more, despite the name.
   *
   * It never proved an email: `registerUser` sets it after a PHONE OTP and
   * `registerUserDirect` sets it at creation with no proof of anything. Use
   * `phoneVerified` / `emailVerified` below for any real decision. Kept because
   * `loginUser` still answers 400 EMAIL_NOT_VERIFIED against it.
   */
  isVerified: boolean;
  /** True only when Google vouched for the inbox. Nothing else sets it. */
  emailVerified?: boolean;
  /**
   * True only once an OTP sent to `phone` was entered.
   *
   * This is what the just-in-time gate reads. A false value is normal, not an
   * error state: an account browses, searches and shortlists perfectly well
   * without it, and is only asked at the first action that needs a real number.
   */
  phoneVerified?: boolean;
  /**
   * Which doors this account can come in by. Values are never sent, only
   * existence.
   *
   * Present on `GET /users/me` and `/users/profile`, ABSENT elsewhere — the
   * underlying fields are `select: false` and only the profile read asks for
   * them. Absent means "not reported", never "none": treating a missing
   * `authMethods` as `{ password: false }` would tell a password user they have
   * no password.
   *
   * Needed because a Google account has no password, so any screen that assumes
   * one — change password, delete account — strands the user without this.
   */
  authMethods?: { password: boolean; google: boolean };
  isBlocked?: boolean;
  isActive?: boolean;
  referralCode?: string;
  preferences?: {
    emailNotifications?: boolean;
    smsNotifications?: boolean;
    [key: string]: unknown;
  };
  lastLogin?: IsoDate;
}

/** One row from `GET /users/sessions`. Reshaped by the controller, not raw. */
export interface UserSessionSummary {
  id: ObjectId;
  device: {
    userAgent?: string;
    platform?: string;
    isMobile?: boolean;
    browser?: string;
  };
  ipAddress: string;
  createdAt: IsoDate;
  lastActivity: IsoDate;
  isCurrent: boolean;
}

// --- Request bodies -------------------------------------------------------

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  /**
   * OPTIONAL since the auth unification, and the app no longer sends it.
   *
   * `registerUserDirect` treats a missing number as valid (`isValidPhoneNumber`
   * returns true for an empty value) and the account is created without one.
   * The number arrives later, through the just-in-time verification sheet, at
   * the first action that actually needs it — collecting it here as well would
   * be asking for the same thing twice.
   *
   * Still required by the LEGACY `/users/register` route, which is the only
   * caller that should set it.
   */
  phone?: string;
  /**
   * LEGACY. Anything other than the literal `"owner"` is normalised to `"user"`.
   * The app no longer sends this: the role is granted server-side on the first
   * listing attempt.
   */
  role?: 'owner' | 'user';
  referralCode?: string;
}

export interface VerifyOtpRequest {
  email: string;
  otp: string;
  /** Carried from the register form so referral attribution is not lost. */
  referralCode?: string;
}

export interface ResendOtpRequest {
  email: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface ForgotPasswordRequest {
  phone: string;
  /** Accepted as fallback if phone is not provided. */
  email?: string;
}

export interface ResetPasswordRequest {
  phone?: string;
  email?: string;
  otp: string;
  newPassword: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

/**
 * `DELETE /users/me`.
 *
 * The password is REQUIRED. `deleteAccount` refuses a body without one
 * (400 `PASSWORD_REQUIRED`) and re-checks it against the hash
 * (401 `INVALID_PASSWORD`) before deleting anything — this is the only
 * confirmation that matters, since a typed phrase proves nothing about who is
 * holding the phone.
 */
export interface DeleteAccountRequest {
  /** Required for an account that has a password. */
  password?: string;
  /**
   * Required INSTEAD for a Google account, which has no password.
   *
   * Must be minted fresh: the backend checks its `sub` against the account's
   * own `googleId`, so a token for a different Google account deletes nothing.
   * Requiring a password here would have left Google accounts permanently
   * undeletable, which fails App Store review as well as the user.
   */
  idToken?: string;
}

export interface DeleteAccountResponse {
  success: true;
  message: string;
  /**
   * Listings the cascade deliberately KEPT: a listing tied to a pending or
   * approved deal verification, or to a live agreement, is evidence in someone
   * else's transaction. Present only when the count is non-zero, and worth
   * showing — the success message promises the listings are gone.
   */
  retainedListings?: number;
}

// --- Google sign-in -------------------------------------------------------

/**
 * `POST /users/auth/google` and `POST /users/auth/google/link`.
 *
 * `idToken` is Google's signed JWT, straight from the native sign-in sheet. The
 * backend verifies it against Google's public keys and reads the email out of
 * the token itself, so sending an email alongside it achieves nothing.
 */
export interface GoogleSignInRequest {
  idToken: string;
  /** Carried through first sign-in so referral attribution is not lost. */
  referralCode?: string;
}

/**
 * The link step, reached only after a 409 `GOOGLE_LINK_REQUIRED`.
 *
 * The existing account's password is what authorises attaching Google to it.
 * The backend will not merge on an email match alone, because registration
 * never verified email and a silent merge would let anyone who squatted your
 * address collect your account.
 */
export interface GoogleLinkRequest {
  idToken: string;
  password: string;
}

// --- Phone verification ---------------------------------------------------

export interface SendPhoneOtpRequest {
  /** Ten digits, no country code. `/^[6-9]\d{9}$/`. */
  phone: string;
}

export interface SendPhoneOtpResponse {
  success: true;
  message: string;
  /** Last two digits, for "ending 47" copy. Absent when already verified. */
  phoneHint?: string;
  expiresInSeconds?: number;
  /** True when this number is already the account's verified number. */
  alreadyVerified?: boolean;
}

export interface VerifyPhoneOtpRequest {
  otp: string;
}

/** `GET /users/phone/status`. For a client resuming mid-flow. */
export interface PhoneStatusResponse {
  success: true;
  phoneVerified: boolean;
  phone: string | null;
  pendingPhoneHint: string | null;
  attemptsRemaining: number | null;
}

// --- Response bodies ------------------------------------------------------

/**
 * `POST /users/login` and `POST /users/verify-otp`.
 *
 * The session is delivered ONLY as a `Set-Cookie` header. No token appears in
 * this body, and none is obtainable any other way. `verify-otp` establishes the
 * session itself, so it must not be followed by a login call.
 */
export interface AuthResponse {
  success: true;
  message: string;
  user: User;
}

/** `POST /users/register`. Creates an unverified user and sends an OTP. */
export interface RegisterResponse {
  success?: boolean;
  message: string;
  email?: string;
}

/** `GET /users/me` and `GET /users/profile`. */
export interface ProfileResponse {
  success: true;
  message: string;
  user: User;
}

/** `GET /users/sessions`. */
export interface SessionsResponse {
  success: true;
  sessions: UserSessionSummary[];
}

// --- Push tokens (Phase 0) ------------------------------------------------

/** `platform` as the backend's push-token model spells it. */
export type PushPlatform = 'ios' | 'android';

/**
 * `POST /users/push-token`. Registers this device's Expo push token against the
 * signed-in account. Re-registering the same token is idempotent and re-points
 * it at the current account, so a phone handed between two logins ends up
 * addressed to whoever is signed in now.
 */
export interface RegisterPushTokenRequest {
  /** `ExponentPushToken[...]`, from `expo-notifications`. */
  token: string;
  platform: PushPlatform;
  /** Stable per-install id, so the backend can tell a reinstall from a new device. */
  installationId?: string;
  appVersion?: string;
}

export interface RegisterPushTokenResponse {
  success: true;
  data: {
    id: ObjectId;
    platform: PushPlatform;
  };
}

/** `DELETE /users/push-token`. Takes a BODY on a DELETE, like `DELETE /users/me`. */
export interface RemovePushTokenRequest {
  token: string;
}

export interface RemovePushTokenResponse {
  success: true;
  removed: boolean;
}

/**
 * `POST /users/logout`. The body is optional; when `pushToken` is present the
 * backend deletes that device token in the same request, so a signed-out phone
 * stops receiving the previous account's notifications.
 */
export interface LogoutRequest {
  pushToken?: string;
}

/**
 * `POST /users/device`. An opaque installation id (16 to 128 url-safe
 * characters) the fraud-linkage check compares across accounts. Sent once per
 * authenticated session with the analytics installation id; nothing else.
 */
export interface RegisterDeviceRequest {
  deviceHash: string;
}

export interface RegisterDeviceResponse {
  success: true;
  message?: string;
}
