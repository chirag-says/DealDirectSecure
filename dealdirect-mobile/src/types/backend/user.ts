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
  isVerified: boolean;
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
  phone: string;
  /** Anything other than the literal `"owner"` is normalised to `"user"`. */
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
