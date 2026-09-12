export {
  AuthProvider,
  useAuth,
  type AuthStatus,
  type GoogleSignInOutcome,
} from './AuthProvider';
export {
  signInWithGoogle,
  forgetGoogleAccount,
  isGoogleSignInConfigured,
  GoogleSignInCancelled,
  GoogleSignInUnavailable,
} from './googleSignIn';
export { isPhoneGateError, requestPhoneVerification, setPhoneGatePresenter } from './phoneGate';
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
export { OwnerOnly, type OwnerOnlyProps } from './components/OwnerOnly';
export { SignInPrompt, type SignInPromptProps } from './components/SignInPrompt';
export { RequireAuth, type RequireAuthProps } from './components/RequireAuth';
export { PhoneVerificationSheet } from './components/PhoneVerificationSheet';
export { GoogleAuthButton, type GoogleAuthButtonProps } from './components/GoogleAuthButton';
export { GoogleLinkSheet, type GoogleLinkSheetProps } from './components/GoogleLinkSheet';

export {
  clearPendingIntent,
  consumePendingIntent,
  hrefForPendingIntent,
  resumeAfterAuth,
  setPendingIntent,
  type PendingIntent,
} from './pendingIntent';
