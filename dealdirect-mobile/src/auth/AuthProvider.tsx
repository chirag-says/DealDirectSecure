import { useQueryClient } from '@tanstack/react-query';
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import {
  ApiError,
  call,
  isSessionFatal,
  setResponseObserver,
  setSessionFatalObserver,
  usersEndpoints,
} from '@/api';
// Imported from the file rather than the `@/notifications` barrel: that barrel
// exports `PushBridge`, which imports `@/auth`, and the cycle would close here.
import {
  clearPushTokenCache,
  peekCachedPushToken,
  registerPushTokenIfPermitted,
  setPushTokenUser,
} from '@/notifications/pushToken';
import { setSentryUser } from '@/observability';
import { clearUserScopedStorage } from '@/storage';
import type { SendPhoneOtpResponse, User } from '@/types/backend/user';
import {
  captureSessionCookie,
  clearSessionCookie,
  hasStoredSession,
  restoreSessionCookie,
} from './cookies';
import { linkDeviceOnce } from './deviceLink';
import { forgetGoogleAccount, signInWithGoogle as googleSignIn } from './googleSignIn';
import type { LoginValues, RegisterValues } from './schemas';

/**
 * Session lifecycle.
 *
 * The backend issues an OPAQUE 48-byte session token as an HttpOnly cookie. It
 * is not a JWT, no endpoint returns it in a body, and there is no refresh
 * endpoint. So there is no token to decode, no expiry to read locally, and no
 * refresh flow to build: the only way to learn whether a session is still valid
 * is to call `GET /users/me`.
 *
 * Cold start therefore runs: re-inject the stored cookie into the native jar,
 * probe /users/me, and treat a 401 as "guest" rather than as an error.
 */

export type AuthStatus = 'restoring' | 'authenticated' | 'guest';

/**
 * The two ways a Google sign-in can legitimately end.
 *
 * `linkRequired` carries the idToken back out because the link call needs the
 * SAME one — re-presenting the Google sheet to obtain a second token would ask
 * the user to pick their account twice for one decision.
 */
export type GoogleSignInOutcome =
  | { status: 'signedIn'; user: User }
  | { status: 'linkRequired'; email: string; idToken: string };

interface AuthContextValue {
  status: AuthStatus;
  user: User | null;
  /** True once the cold-start probe has finished, however it finished. */
  isReady: boolean;
  login: (values: LoginValues) => Promise<User>;
  /**
   * The one registration path. Creates the account and the session in a single
   * call, with no OTP and no phone number.
   *
   * There used to be a second, `register`, for the owner branch of the old
   * two-role signup form. It is gone with that form: the role is granted
   * server-side on the first listing, and the phone is verified just in time.
   * `/users/register` stays live on the backend for published builds that still
   * call it, but nothing in this app does.
   */
  registerDirect: (values: RegisterValues) => Promise<User>;
  verifyOtp: (email: string, otp: string, referralCode?: string) => Promise<User>;
  resendOtp: (email: string) => Promise<void>;
  /**
   * Presents the Google sheet and exchanges the token for a session.
   *
   * Two outcomes, both normal. `signedIn` is the common one. `linkRequired`
   * means the email already has a password account, no session was issued, and
   * the caller must collect that password and call `linkGoogleAccount` with the
   * SAME `idToken`. That is a step in the flow, not a failure: the backend
   * refuses to merge on an email match alone because registration never
   * verified email, so an unlinked account could belong to anyone.
   */
  signInWithGoogle: (referralCode?: string) => Promise<GoogleSignInOutcome>;
  linkGoogleAccount: (idToken: string, password: string) => Promise<User>;
  /** Just-in-time phone link. Used by the verification sheet, not by screens. */
  sendPhoneOtp: (phone: string) => Promise<SendPhoneOtpResponse>;
  verifyPhoneOtp: (otp: string) => Promise<User>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  /** Reason the last session ended, for an explanatory message on the login screen. */
  endedReason: string | null;
  clearEndedReason: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Requests this provider makes on its own behalf, and already handles.
 *
 * Two reasons a path is here. `/users/me` is the session probe: all three call
 * sites below catch a dead session themselves and choose the right outcome
 * (silent on cold start, explanatory after login), so letting the global
 * handler fire as well would race them and overwrite the reason. `/users/login`
 * and the registration pair answer bad credentials with a 401 carrying no code,
 * which normalises to `session` — indistinguishable, from the transport layer,
 * from a revoked cookie. Logout needs no teardown announcement; it is one.
 */
const AUTH_OWNED_PATHS = [
  '/users/me',
  '/users/login',
  '/users/logout',
  '/users/register',
  '/users/register-direct',
  '/users/verify-otp',
  // Google sign-in answers a rejected token with 401 GOOGLE_INVALID_TOKEN,
  // which normalises to `session` on status alone. It says nothing about the
  // app's own cookie — there usually is not one yet — and the caller below
  // already turns it into a message on the sign-in screen.
  '/users/auth/google',
] as const;

function isAuthOwnedPath(url: string): boolean {
  return AUTH_OWNED_PATHS.some((path) => url.startsWith(path));
}

/** Shown on the login screen after a session ends underneath the user. */
const SESSION_ENDED_MESSAGE = 'Your session ended. Please sign in again.';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AuthStatus>('restoring');
  const [user, setUser] = useState<User | null>(null);
  const [endedReason, setEndedReason] = useState<string | null>(null);

  // Guards against several concurrent 401s each triggering their own teardown.
  const endingRef = useRef(false);

  // The global handler below runs outside React's render cycle, so it cannot
  // close over `status` without going stale. A ref is the current value.
  const statusRef = useRef<AuthStatus>('restoring');
  useEffect(() => {
    statusRef.current = status;
  }, [status]);

  const endSession = useCallback(
    async (reason: string | null) => {
      if (endingRef.current) return;
      endingRef.current = true;

      try {
        await clearSessionCookie();
        clearUserScopedStorage();
        // The backend may or may not still hold this device's push token (a
        // revoked session says nothing about it), but this app no longer has
        // an account to register it for. Forgetting it locally means the next
        // sign-in re-posts rather than trusting a stale record.
        clearPushTokenCache();
        queryClient.clear();
        setUser(null);
        setEndedReason(reason);
        setStatus('guest');
      } finally {
        endingRef.current = false;
      }
    },
    [queryClient]
  );

  /**
   * Mirrors the native cookie jar into secure storage after every response.
   *
   * Runs on responses rather than only after login because the backend can
   * reissue the cookie at any point, and a mirror that only tracks login would
   * drift out of date.
   */
  useEffect(() => {
    setResponseObserver(() => {
      void captureSessionCookie();
    });

    /**
     * One dead-session response from anywhere in the app ends the session.
     *
     * Guarded twice, because the cost of a false positive is throwing out a
     * working session. A guest cannot be logged out, so nothing happens unless
     * the app currently believes it is authenticated — which is also what keeps
     * a failed login (401, no code) from tearing down the screen the user is
     * standing on. And the calls this provider makes itself are excluded, since
     * each already handles the same failure with better information.
     */
    setSessionFatalObserver((error, url) => {
      if (statusRef.current !== 'authenticated') return;
      if (isAuthOwnedPath(url)) return;
      void endSession(error.details.blockReason ?? SESSION_ENDED_MESSAGE);
    });

    return () => {
      setResponseObserver(null);
      setSessionFatalObserver(null);
    };
  }, [endSession]);

  /**
   * Side effects of the session's identity, kept out of the state setters so
   * every path that changes the user (cold start, login, refresh, teardown)
   * pays them once here. Three consumers: crash reports carry `{ id, role }`
   * and nothing else, push registration knows whom to register for, and the
   * install is linked to the account for the close-deal fraud check. The
   * last two are fire-and-forget and prompt for nothing; the push one only
   * posts a token the OS has already been allowed to issue, and the device
   * link is sent once per (install, account) and never again.
   */
  useEffect(() => {
    setSentryUser(user ? { id: user._id, role: user.role } : null);
    setPushTokenUser(user?._id ?? null);
    if (status === 'authenticated' && user) {
      void registerPushTokenIfPermitted();
      void linkDeviceOnce(user._id);
    }
  }, [status, user]);

  const fetchMe = useCallback(async (): Promise<User> => {
    const response = await call(usersEndpoints.me);
    return response.user;
  }, []);

  /** Cold start. A 401 here is the normal guest path, not a failure. */
  useEffect(() => {
    let cancelled = false;

    const restore = async () => {
      try {
        if (!(await hasStoredSession())) {
          if (!cancelled) setStatus('guest');
          return;
        }

        await restoreSessionCookie();
        const me = await fetchMe();

        if (cancelled) return;
        setUser(me);
        setStatus('authenticated');
      } catch (error) {
        if (cancelled) return;

        if (error instanceof ApiError && isSessionFatal(error)) {
          // Expired or revoked while the app was closed. Silent: the user did
          // nothing wrong and does not need an error about it.
          await endSession(null);
          return;
        }

        // Offline at launch. The stored cookie may still be perfectly good, so
        // it is NOT cleared; the user is simply treated as a guest until a
        // later request can confirm.
        setStatus('guest');
      }
    };

    void restore();
    return () => {
      cancelled = true;
    };
  }, [fetchMe, endSession]);

  /**
   * Turns a just-issued session into a CONFIRMED one.
   *
   * A 200 from `/users/login` is not proof that this app is authenticated. The
   * session arrives only as a `Set-Cookie` that the native jar has to accept,
   * and if it did not, every later request 401s while the login screen has
   * already navigated away. To the user that is indistinguishable from "login
   * silently does nothing" — the screen succeeds, the app is logged out, and
   * nothing anywhere says why.
   *
   * So the session is proven rather than assumed: mirror the cookie, then make
   * one real authenticated request. `/users/me` is the same probe the cold-start
   * path uses and it returns the fresh user, so the cost is one round trip and
   * the failure becomes legible on the screen that caused it.
   *
   * `fallbackUser` is the user object the issuing endpoint already returned. It
   * is used only when the probe fails for a reason that says nothing about the
   * cookie — see below.
   */
  const establishSession = useCallback(
    async (fallbackUser: User): Promise<User> => {
      const mirrored = await captureSessionCookie();

      let confirmed: User;
      try {
        confirmed = await fetchMe();
      } catch (error) {
        // Only a REJECTED session means the credential did not take. A network
        // drop or a 5xx between the two calls is not evidence against the
        // cookie, and refusing a login that actually worked would be the worse
        // failure of the two — so those fall through to the user the issuing
        // endpoint already gave us.
        if (error instanceof ApiError && isSessionFatal(error)) {
          await endSession(null);
          throw new ApiError({
            kind: 'session',
            message:
              'Signed in, but this device could not keep you signed in. ' +
              'Please try again.',
          });
        }
        confirmed = fallbackUser;
      }

      // The mirror is only what survives a COLD START. Losing it is degraded,
      // not broken: this run is fully authenticated and only the next launch
      // would ask for a password again. Not worth failing a working login over,
      // but worth a line in the log, because it is the signal that the native
      // cookie jar and secure storage have stopped agreeing.
      if (!mirrored) {
        console.warn(
          '[auth] session established but not mirrored to secure storage; ' +
            'the next cold start will require logging in again'
        );
      }

      setUser(confirmed);
      setEndedReason(null);
      setStatus('authenticated');
      return confirmed;
    },
    [fetchMe, endSession]
  );

  const login = useCallback(
    async (values: LoginValues): Promise<User> => {
      const response = await call(usersEndpoints.login, { data: values });
      return establishSession(response.user);
    },
    [establishSession]
  );

  const registerDirect = useCallback(async (values: RegisterValues): Promise<User> => {
    // Creates a VERIFIED buyer account and ESTABLISHES THE SESSION via Set-Cookie.
    // Goes through establishSession to confirm the cookie took, same as login.
    const response = await call(usersEndpoints.registerDirect, { data: values });
    return establishSession(response.user);
  }, [establishSession]);

  const verifyOtp = useCallback(
    async (email: string, otp: string, referralCode?: string): Promise<User> => {
      const response = await call(usersEndpoints.verifyOtp, {
        data: { email, otp, referralCode },
      });
      return establishSession(response.user);
    },
    [establishSession]
  );

  const resendOtp = useCallback(async (email: string): Promise<void> => {
    await call(usersEndpoints.resendOtp, { data: { email } });
  }, []);

  const signInWithGoogle = useCallback(
    async (referralCode?: string): Promise<GoogleSignInOutcome> => {
      // Google's sheet first. Cancellation and "this build cannot do Google"
      // both throw their own error types, which the screen distinguishes.
      const idToken = await googleSignIn();

      try {
        const response = await call(usersEndpoints.googleSignIn, {
          data: { idToken, referralCode },
        });
        return { status: 'signedIn', user: await establishSession(response.user) };
      } catch (error) {
        if (error instanceof ApiError && error.code === 'GOOGLE_LINK_REQUIRED') {
          // Not a failure. The email has a password account that has not been
          // linked, and proving it is the next step. The token travels back out
          // so the link call reuses it rather than asking Google again.
          return { status: 'linkRequired', email: error.details.email ?? '', idToken };
        }
        throw error;
      }
    },
    [establishSession]
  );

  const linkGoogleAccount = useCallback(
    async (idToken: string, password: string): Promise<User> => {
      const response = await call(usersEndpoints.googleLink, { data: { idToken, password } });
      return establishSession(response.user);
    },
    [establishSession]
  );

  const sendPhoneOtp = useCallback(async (phone: string) => {
    return call(usersEndpoints.sendPhoneOtp, { data: { phone } });
  }, []);

  const verifyPhoneOtp = useCallback(async (otp: string): Promise<User> => {
    const response = await call(usersEndpoints.verifyPhoneOtp, { data: { otp } });
    // The session is already live; only the user changed. Set it directly
    // rather than going through establishSession, which would re-probe a cookie
    // that was never in question and cost a round trip inside a sheet the user
    // is waiting on.
    setUser(response.user);
    return response.user;
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    try {
      // The device token rides along so the backend drops it in the same
      // request: a signed-out phone must not keep receiving this account's
      // notifications. `endSession` clears the local copy afterwards.
      const pushToken = peekCachedPushToken();
      await call(usersEndpoints.logout, { data: pushToken ? { pushToken } : undefined });
    } catch {
      // A failed logout call must still clear the device. Leaving a session
      // mirrored locally because the network was down is the worse outcome.
    }
    // Clear Google's own cached account too. Without this its session outlives
    // the DealDirect one, and the next person to open the app on a shared
    // device is offered the previous user's account as the obvious choice.
    await forgetGoogleAccount();
    await endSession(null);
  }, [endSession]);

  const refreshUser = useCallback(async (): Promise<void> => {
    try {
      setUser(await fetchMe());
    } catch (error) {
      if (error instanceof ApiError && isSessionFatal(error)) {
        await endSession(error.details.blockReason ?? error.message);
      }
    }
  }, [fetchMe, endSession]);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      isReady: status !== 'restoring',
      login,
      registerDirect,
      verifyOtp,
      resendOtp,
      signInWithGoogle,
      linkGoogleAccount,
      sendPhoneOtp,
      verifyPhoneOtp,
      logout,
      refreshUser,
      endedReason,
      clearEndedReason: () => setEndedReason(null),
    }),
    [
      status,
      user,
      login,
      registerDirect,
      verifyOtp,
      resendOtp,
      signInWithGoogle,
      linkGoogleAccount,
      sendPhoneOtp,
      verifyPhoneOtp,
      logout,
      refreshUser,
      endedReason,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return context;
}
