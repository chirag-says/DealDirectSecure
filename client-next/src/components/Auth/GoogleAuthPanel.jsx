'use client';

import { useState } from 'react';

import { useAuth } from '../../context/AuthContext';
import GoogleLinkModal from './GoogleLinkModal';
import GoogleSignInButton from './GoogleSignInButton';

/**
 * The whole Google entry point: button, the link step, and the divider.
 *
 * One component because the login page, the register page and the auth modal
 * all need exactly the same three pieces wired the same way. Three copies would
 * drift — and the piece most likely to be dropped from a copy is the link step,
 * whose absence turns a 409 into a dead end that looks like a broken button.
 *
 * Renders nothing at all when `NEXT_PUBLIC_GOOGLE_CLIENT_ID` is unset: the
 * button hides itself, and the divider follows it rather than being left
 * stranded above the email form announcing an alternative that is not there.
 */
export default function GoogleAuthPanel({ referralCode, onSuccess, dividerLabel }) {
  const { signInWithGoogle } = useAuth();
  const [pendingLink, setPendingLink] = useState(null);
  const [error, setError] = useState('');

  const configured = Boolean(process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID);
  if (!configured) return null;

  const onCredential = async (idToken) => {
    setError('');
    const result = await signInWithGoogle(idToken, referralCode);

    if (result.success) {
      onSuccess(result.user);
      return;
    }

    // Not a failure: the email has a password account that has not been linked,
    // and proving it is the next step. The token is carried into the modal so
    // the link call reuses it rather than asking Google a second time.
    if (result.linkRequired) {
      setPendingLink({ email: result.email, idToken });
      return;
    }

    if (result.errorData?.code === 'GOOGLE_EMAIL_NOT_VERIFIED') {
      setError(
        'That Google account has no verified email address. Please sign in with email and password instead.'
      );
      return;
    }

    setError(result.message || 'Google sign-in failed. Please try again.');
  };

  return (
    <>
      <GoogleSignInButton onCredential={onCredential} />

      {error ? <p className="mt-2 text-center text-sm text-red-600">{error}</p> : null}

      <div className="my-5 flex items-center gap-3">
        <span className="h-px flex-1 bg-slate-200" />
        <span className="text-xs uppercase tracking-wide text-slate-500">
          {dividerLabel || 'or'}
        </span>
        <span className="h-px flex-1 bg-slate-200" />
      </div>

      <GoogleLinkModal
        pending={pendingLink}
        onClose={() => setPendingLink(null)}
        onLinked={(user) => {
          setPendingLink(null);
          onSuccess(user);
        }}
      />
    </>
  );
}
