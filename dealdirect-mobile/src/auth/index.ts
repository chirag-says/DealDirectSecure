export { AuthProvider, useAuth, type AuthStatus } from './AuthProvider';
export {
  captureSessionCookie,
  restoreSessionCookie,
  clearSessionCookie,
  hasStoredSession,
} from './cookies';
export {
  loginSchema,
  registerSchema,
  verifyOtpSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  passwordSchema,
  emailSchema,
  phoneSchema,
  normalizeIndianMobile,
  otpSchema,
  type LoginValues,
  type RegisterValues,
  type VerifyOtpValues,
  type ForgotPasswordValues,
  type ResetPasswordValues,
} from './schemas';

export { AuthShell, type AuthShellProps } from './components/AuthShell';
export { AuthResult, type AuthResultProps, type AuthResultTone } from './components/AuthResult';
export { SignInPrompt, type SignInPromptProps } from './components/SignInPrompt';
