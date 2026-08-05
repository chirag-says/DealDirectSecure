import { z } from 'zod';

/**
 * Auth form validation.
 *
 * These MIRROR the backend's rules (`validatePasswordStrength` and
 * `isValidPhoneNumber` in controllers/userController.js). They exist to give
 * immediate feedback, not to enforce anything: the backend remains the
 * authority and re-checks everything.
 *
 * Keeping them identical matters in one direction specifically. If the client
 * were LOOSER, the user would be told a password is fine and then rejected on
 * submit. If it were STRICTER, the user would be blocked from a password the
 * backend would have accepted.
 */

/** Backend: /[@$!%*?&#^()\-_=+]/ — copied character for character. */
const SPECIAL_CHARACTERS = '@$!%*?&#^()-_=+';

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/\d/, 'Password must contain at least one number')
  .regex(
    /[@$!%*?&#^()\-_=+]/,
    `Password must contain at least one special character (${SPECIAL_CHARACTERS})`
  );

export const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .email('Enter a valid email address')
  .transform((value) => value.toLowerCase().trim());

/** Backend: /^[6-9]\d{9}$/ — an Indian mobile number, no country code. */
export const phoneSchema = z
  .string()
  .trim()
  .regex(/^[6-9]\d{9}$/, 'Enter a valid 10-digit mobile number');

/** Backend generates via crypto.randomInt(100000, 999999): always 6 digits. */
export const otpSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, 'Enter the 6-digit code');

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
});

export const registerSchema = z.object({
  name: z.string().trim().min(2, 'Enter your name'),
  email: emailSchema,
  phone: phoneSchema,
  password: passwordSchema,
  // Backend normalises anything that is not the literal "owner" to "user".
  // No `.default()` here: it would make the parsed INPUT type optional while
  // the OUTPUT type stayed required, which react-hook-form's resolver rejects.
  // The form supplies the initial value instead.
  role: z.enum(['user', 'owner']),
  referralCode: z.string().trim().optional(),
});

export const verifyOtpSchema = z.object({
  otp: otpSchema,
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export type LoginValues = z.infer<typeof loginSchema>;
export type RegisterValues = z.infer<typeof registerSchema>;
export type VerifyOtpValues = z.infer<typeof verifyOtpSchema>;
export type ForgotPasswordValues = z.infer<typeof forgotPasswordSchema>;
