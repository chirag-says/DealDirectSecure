'use client';

import { useState } from 'react';
import { KeyRound, X } from 'lucide-react';

import { useAuth } from '../../context/AuthContext';

/**
 * "This email already has an account. Enter its password to connect Google."
 *
 * ---------------------------------------------------------------------------
 * WHY THE PASSWORD IS ASKED FOR AT ALL
 *
 * Merging the two silently would be friendlier. Google verified the email, so
 * the person owns the inbox, so it must be them.
 *
 * Except registration on this site has never verified email — neither
 * `registerUser` nor `registerUserDirect` checks that whoever signed up can
 * read the address they typed. An account under your Gmail can therefore have
 * been created by anyone. Merging on an email match would drop the real owner
 * into a stranger's account: one whose password the stranger still knows, and
 * whose contents they could then read at leisure, with nothing visible
 * happening to either party.
 *
 * One password entry, once, ever. Five seconds for the real owner, impossible
 * for someone who is not them.
 */
export default function GoogleLinkModal({ pending, onClose, onLinked }) {
  const { linkGoogle } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (!pending) return null;

  const close = () => {
    setPassword('');
    setError('');
    onClose();
  };

  const onSubmit = async (event) => {
    event?.preventDefault();

    if (!password) {
      setError('Enter your password.');
      return;
    }

    setError('');
    setBusy(true);
    try {
      const result = await linkGoogle(pending.idToken, password);
      if (result.success) {
        setPassword('');
        onLinked(result.user);
        return;
      }

      const code = result.errorData?.code;
      if (code === 'ACCOUNT_LOCKED') {
        // This endpoint shares the password-login lockout counter on purpose,
        // so a run of wrong guesses locks the account exactly as it would on
        // the login form. Say how long rather than repeating "wrong".
        const until = result.errorData?.lockoutUntil;
        const minutes = until
          ? Math.max(1, Math.ceil((new Date(until).getTime() - Date.now()) / 60000))
          : 15;
        setError(`Too many attempts. Try again in about ${minutes} minutes.`);
        return;
      }
      if (code === 'GOOGLE_ALREADY_LINKED') {
        setError('This account is already connected to a different Google account.');
        return;
      }

      setError(result.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/60 p-4 backdrop-blur-sm">
      <form onSubmit={onSubmit} className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-50">
              <KeyRound className="h-5 w-5 text-blue-600" />
            </span>
            <h2 className="text-lg font-semibold text-slate-900">
              Connect Google to your account
            </h2>
          </div>
          <button
            type="button"
            onClick={close}
            aria-label="Close"
            className="rounded-lg p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="mb-5 text-sm text-slate-600">
          {pending.email ? (
            <>
              <span className="font-medium text-slate-900">{pending.email}</span> already has a
              DealDirect account. Enter its password once and Google will be connected to it.
            </>
          ) : (
            'This email already has a DealDirect account. Enter its password once and Google will be connected to it.'
          )}
        </p>

        <label className="block">
          <span className="mb-1.5 block text-sm font-medium text-slate-700">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Your existing password"
            className="w-full rounded-xl border-2 border-slate-200 px-3 py-2.5 text-slate-900 outline-none focus:border-blue-500"
          />
        </label>

        {error ? <p className="mt-2 text-sm text-red-600">{error}</p> : null}

        <button
          type="submit"
          disabled={busy}
          className="mt-5 w-full rounded-xl bg-blue-600 px-4 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
        >
          {busy ? 'Connecting…' : 'Connect and sign in'}
        </button>

        <p className="mt-3 text-center text-xs text-slate-500">
          You will only be asked this once. After connecting, either sign-in method works.
        </p>
      </form>
    </div>
  );
}
