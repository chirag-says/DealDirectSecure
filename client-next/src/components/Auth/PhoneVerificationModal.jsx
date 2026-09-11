'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Phone, ShieldCheck, X } from 'lucide-react';

import { useAuth } from '../../context/AuthContext';
import { setPhoneVerificationPresenter } from '../../utils/api';

/**
 * The just-in-time phone gate, as the visitor sees it.
 *
 * Mounted once, in the root layout. No page renders it and no route reaches it:
 * the axios response interceptor raises it when the backend refuses a gated
 * action, and the request that was refused replays itself once this resolves.
 * That is why it is a modal over the current page rather than a route — sending
 * someone to /verify-phone would lose the listing they were standing on, which
 * is the exact failure this design exists to prevent.
 *
 * ---------------------------------------------------------------------------
 * THE LIMITS ARE SHOWN, NOT ENFORCED SILENTLY
 *
 * The backend allows three sends per fifteen minutes and burns a code after
 * five wrong guesses. A code that simply stops working reads as a broken site;
 * "2 attempts left" reads as a rule. The 45-second cooldown here paces the
 * visitor without being the thing that refuses them, which is the server's job.
 */

const RESEND_COOLDOWN_SECONDS = 45;

/** Ten digits, no country code. Mirrors the backend's /^[6-9]\d{9}$/. */
const PHONE_PATTERN = /^[6-9]\d{9}$/;

/**
 * A pasted number reduced to the ten digits the backend wants.
 *
 * Numbers arrive from a contacts app or a clipboard as "+91 98765 43210" or
 * "098765-43210". Rejecting a correct number because of how it was formatted is
 * the most irritating failure a form has.
 */
const normalizeIndianMobile = (raw) => {
  const digits = (raw || '').replace(/\D/g, '');
  if (digits.length > 10 && digits.startsWith('91')) return digits.slice(2, 12);
  if (digits.length > 10 && digits.startsWith('0')) return digits.slice(1, 11);
  return digits.slice(0, 10);
};

export default function PhoneVerificationModal() {
  const { sendPhoneOtp, verifyPhoneOtp } = useAuth();

  const [open, setOpen] = useState(false);
  const [stage, setStage] = useState('phone');
  const [phone, setPhone] = useState('');
  const [otp, setOtp] = useState('');
  const [hint, setHint] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  /**
   * How this modal answers the request that raised it.
   *
   * A ref rather than state: it must survive re-renders untouched and be
   * callable from the close handler without React having closed over a stale
   * value. Cleared as it is called, so closing twice cannot resolve the same
   * request twice.
   */
  const resolveRef = useRef(null);

  const settle = useCallback((verified) => {
    const resolve = resolveRef.current;
    resolveRef.current = null;
    setOpen(false);
    if (resolve) resolve(verified);
  }, []);

  useEffect(() => {
    setPhoneVerificationPresenter(
      () =>
        new Promise((resolve) => {
          resolveRef.current = resolve;
          setStage('phone');
          setPhone('');
          setOtp('');
          setHint('');
          setError('');
          setCooldown(0);
          setOpen(true);
        })
    );

    return () => {
      setPhoneVerificationPresenter(null);
      // Unmounting with a request still waiting would hang it forever. Answer
      // "not verified" so the original 403 surfaces on the page instead.
      if (resolveRef.current) resolveRef.current(false);
      resolveRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const timer = setTimeout(() => setCooldown((value) => value - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Escape closes, as it does on every other dialog. Treated as "not now".
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event) => {
      if (event.key === 'Escape') settle(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, settle]);

  if (!open) return null;

  const describe = (err, fallback) => err?.response?.data?.message || fallback;

  const onSendCode = async () => {
    if (!PHONE_PATTERN.test(phone)) {
      setError('Enter a valid 10-digit mobile number.');
      return;
    }

    setError('');
    setBusy(true);
    try {
      const response = await sendPhoneOtp(phone);

      // Already this account's verified number. Nothing was sent, nothing needs
      // verifying, so the gate simply opens.
      if (response?.alreadyVerified) {
        settle(true);
        return;
      }

      setHint(response?.phoneHint || phone.slice(-2));
      setStage('code');
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err) {
      setError(describe(err, 'Could not send the verification code.'));
    } finally {
      setBusy(false);
    }
  };

  const onResend = async () => {
    setError('');
    setBusy(true);
    try {
      await sendPhoneOtp(phone);
      setOtp('');
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err) {
      setError(describe(err, 'Could not resend the code.'));
    } finally {
      setBusy(false);
    }
  };

  const onVerify = async () => {
    if (!/^\d{6}$/.test(otp)) {
      setError('Enter the 6-digit code.');
      return;
    }

    setError('');
    setBusy(true);
    try {
      await verifyPhoneOtp(otp);
      settle(true);
    } catch (err) {
      const data = err?.response?.data;
      const remaining = data?.attemptsRemaining;

      setError(
        typeof remaining === 'number' && remaining > 0
          ? `${data.message} ${remaining} ${remaining === 1 ? 'attempt' : 'attempts'} left.`
          : describe(err, 'Verification failed. Please try again.')
      );

      // A burned or expired code cannot be retyped into working. Go back to the
      // number so the obvious next action is requesting a new one.
      if (data?.code === 'OTP_EXPIRED' || data?.code === 'OTP_ATTEMPTS_EXCEEDED') {
        setStage('phone');
        setOtp('');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-50">
              <ShieldCheck className="h-5 w-5 text-blue-600" />
            </span>
            <h2 className="text-lg font-semibold text-slate-900">Verify your mobile number</h2>
          </div>
          <button
            type="button"
            onClick={() => settle(false)}
            aria-label="Close"
            className="rounded-lg p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="mb-5 text-sm text-slate-600">
          {stage === 'phone'
            ? 'A one-time check. We use it to confirm a real person is behind this account before you list, enquire or claim a reward.'
            : `Enter the 6-digit code we sent to the number ending ${hint}. It expires in 10 minutes.`}
        </p>

        {stage === 'phone' ? (
          <label className="block">
            <span className="mb-1.5 block text-sm font-medium text-slate-700">Mobile number</span>
            <div className="flex items-center rounded-xl border-2 border-slate-200 focus-within:border-blue-500">
              <span className="flex items-center gap-1.5 border-r border-slate-200 px-3 py-2.5 text-sm text-slate-500">
                <Phone className="h-4 w-4" />
                +91
              </span>
              <input
                type="tel"
                inputMode="numeric"
                autoComplete="tel"
                maxLength={10}
                value={phone}
                onChange={(event) => setPhone(normalizeIndianMobile(event.target.value))}
                onKeyDown={(event) => event.key === 'Enter' && onSendCode()}
                placeholder="9876543210"
                className="w-full rounded-r-xl px-3 py-2.5 text-slate-900 outline-none"
              />
            </div>
          </label>
        ) : (
          <label className="block">
            <span className="mb-1.5 block text-sm font-medium text-slate-700">
              Verification code
            </span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={otp}
              onChange={(event) => setOtp(event.target.value.replace(/\D/g, ''))}
              onKeyDown={(event) => event.key === 'Enter' && onVerify()}
              placeholder="123456"
              className="w-full rounded-xl border-2 border-slate-200 px-3 py-2.5 tracking-[0.4em] text-slate-900 outline-none focus:border-blue-500"
            />
          </label>
        )}

        {error ? <p className="mt-2 text-sm text-red-600">{error}</p> : null}

        <button
          type="button"
          disabled={busy}
          onClick={stage === 'phone' ? onSendCode : onVerify}
          className="mt-5 w-full rounded-xl bg-blue-600 px-4 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
        >
          {busy ? 'Please wait…' : stage === 'phone' ? 'Send code' : 'Verify and continue'}
        </button>

        {stage === 'code' ? (
          <button
            type="button"
            disabled={cooldown > 0 || busy}
            onClick={onResend}
            className="mt-3 w-full text-sm text-blue-600 transition hover:text-blue-700 disabled:text-slate-400"
          >
            {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
          </button>
        ) : null}

        <button
          type="button"
          onClick={() => settle(false)}
          className="mt-3 w-full text-sm text-slate-500 transition hover:text-slate-700"
        >
          Not now
        </button>
      </div>
    </div>
  );
}
