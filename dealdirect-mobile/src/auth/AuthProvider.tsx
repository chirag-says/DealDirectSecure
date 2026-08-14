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

import { ApiError, call, isSessionFatal, setResponseObserver, usersEndpoints } from '@/api';
import { clearUserScopedStorage } from '@/storage';
import type { User } from '@/types/backend/user';
import {
  captureSessionCookie,
  clearSessionCookie,
  hasStoredSession,
  restoreSessionCookie,
} from './cookies';
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

interface AuthContextValue {
  status: AuthStatus;
  user: User | null;
  /** True once the cold-start probe has finished, however it finished. */
  isReady: boolean;
  login: (values: LoginValues) => Promise<User>;
  register: (values: RegisterValues) => Promise<void>;
  /** Buyer registration — creates account and session in one call, no OTP. */
  registerDirect: (values: RegisterValues) => Promise<User>;
  verifyOtp: (email: string, otp: string, referralCode?: string) => Promise<User>;
  resendOtp: (email: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  /** Reason the last session ended, for an explanatory message on the login screen. */
  endedReason: string | null;
  clearEndedReason: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AuthStatus>('restoring');
  const [user, setUser] = useState<User | null>(null);
  const [endedReason, setEndedReason] = useState<string | null>(null);

  // Guards against several concurrent 401s each triggering their own teardown.
  const endingRef = useRef(false);

  const endSession = useCallback(
    async (reason: string | null) => {
      if (endingRef.current) return;
      endingRef.current = true;

      try {
        await clearSessionCookie();
        clearUserScopedStorage();
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
    return () => setResponseObserver(null);
  }, []);

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

  const register = useCallback(async (values: RegisterValues): Promise<void> => {
    // Creates an UNVERIFIED account and sends an OTP. No session yet; verifyOtp
    // is what establishes one.
    await call(usersEndpoints.register, { data: values });
  }, []);

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

  const logout = useCallback(async (): Promise<void> => {
    try {
      await call(usersEndpoints.logout);
    } catch {
      // A failed logout call must still clear the device. Leaving a session
      // mirrored locally because the network was down is the worse outcome.
    }
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
      register,
      registerDirect,
      verifyOtp,
      resendOtp,
      logout,
      refreshUser,
      endedReason,
      clearEndedReason: () => setEndedReason(null),
    }),
    [status, user, login, register, registerDirect, verifyOtp, resendOtp, logout, refreshUser, endedReason]
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
