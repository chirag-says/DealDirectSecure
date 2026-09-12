import { useCallback, useEffect, useRef, useState } from 'react';
import { Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import { gesture } from '@/theme';
import { Button, Input, Sheet, Text } from '@/ui';
import { normalizeIndianMobile, otpSchema, phoneSchema } from '../schemas';
import { setPhoneGatePresenter } from '../phoneGate';
import { useAuth } from '../AuthProvider';

/**
 * The just-in-time phone gate, as the user sees it.
 *
 * Mounted once, near the root. It is not routed to and no screen renders it:
 * `call()` raises it when the backend refuses a gated action, and the request
 * that was refused replays itself once this resolves. That is why it is a sheet
 * over the current screen rather than a route — routing away would lose the
 * listing the user was standing on, which is the whole thing this design
 * exists to avoid.
 *
 * ---------------------------------------------------------------------------
 * WHY THE RESEND COOLDOWN IS 45 SECONDS AND THE CAP IS REAL
 *
 * The backend allows three sends per fifteen minutes per account and burns a
 * code after five wrong guesses. Both limits are shown rather than enforced
 * silently: a code that simply stops working reads as a broken app, whereas
 * "2 attempts left" reads as a rule. The cooldown here is shorter than the
 * backend's window on purpose — it paces the user without being the thing that
 * refuses them, which is the server's job.
 */

const RESEND_COOLDOWN_SECONDS = 45;

type Stage = 'phone' | 'code';

export function PhoneVerificationSheet() {
  const { sendPhoneOtp, verifyPhoneOtp } = useAuth();

  const [visible, setVisible] = useState(false);
  const [stage, setStage] = useState<Stage>('phone');
  const [phone, setPhone] = useState('');
  const [otp, setOtp] = useState('');
  const [hint, setHint] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  /**
   * How the sheet answers the request that raised it.
   *
   * Held in a ref rather than state because it must survive re-renders
   * untouched and must be callable from the close handler, which React would
   * otherwise have closed over at a stale value. Cleared as it is called, so a
   * second close cannot resolve the same request twice.
   */
  const resolveRef = useRef<((verified: boolean) => void) | null>(null);

  const settle = useCallback((verified: boolean) => {
    const resolve = resolveRef.current;
    resolveRef.current = null;
    setVisible(false);
    resolve?.(verified);
  }, []);

  /** Registered with the gate so `call()` can raise this from anywhere. */
  useEffect(() => {
    setPhoneGatePresenter(
      () =>
        new Promise<boolean>((resolve) => {
          resolveRef.current = resolve;
          setStage('phone');
          setPhone('');
          setOtp('');
          setHint(null);
          setError(null);
          setCooldown(0);
          setVisible(true);
        })
    );

    return () => {
      setPhoneGatePresenter(null);
      // Unmounting with a request still waiting would hang it forever. Answer
      // "not verified" so the original 403 surfaces on the screen instead.
      resolveRef.current?.(false);
      resolveRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((value) => value - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const describe = (err: unknown, fallback: string): string =>
    err instanceof ApiError ? err.message : fallback;

  const onSendCode = async () => {
    const parsed = phoneSchema.safeParse(phone);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? 'Enter a valid 10-digit mobile number.');
      return;
    }

    setError(null);
    setBusy(true);
    try {
      const response = await sendPhoneOtp(parsed.data);

      // The number was already this account's verified number. Nothing was
      // sent and nothing needs verifying, so the gate simply opens.
      if (response.alreadyVerified) {
        settle(true);
        return;
      }

      setHint(response.phoneHint ?? parsed.data.slice(-2));
      setStage('code');
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err) {
      setError(describe(err, 'Could not send the verification code.'));
    } finally {
      setBusy(false);
    }
  };

  const onResend = async () => {
    setError(null);
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
    const parsed = otpSchema.safeParse(otp);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? 'Enter the 6-digit code.');
      return;
    }

    setError(null);
    setBusy(true);
    try {
      await verifyPhoneOtp(parsed.data);
      settle(true);
    } catch (err) {
      if (err instanceof ApiError) {
        // The backend counts down and then burns the code. Saying how many
        // guesses remain is the difference between a rule and a malfunction.
        const remaining = err.details.attemptsRemaining;
        setError(
          typeof remaining === 'number' && remaining > 0
            ? `${err.message} ${remaining} ${remaining === 1 ? 'attempt' : 'attempts'} left.`
            : err.message
        );

        // A burned or expired code cannot be retyped into working. Send the
        // user back to the number so the obvious next action is a new code.
        if (err.code === 'OTP_EXPIRED' || err.code === 'OTP_ATTEMPTS_EXCEEDED') {
          setStage('phone');
          setOtp('');
        }
        return;
      }
      setError('Verification failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet
      visible={visible}
      onClose={() => settle(false)}
      title="Verify your mobile number"
      heightRatio={0.62}
    >
      <View className="gap-sm">
        <Text variant="callout" tone="secondary">
          {stage === 'phone'
            ? 'One-time check. We use it to confirm a real person is behind this account before you list, enquire or claim a reward.'
            : `Enter the 6-digit code we sent to the number ending ${hint}. It expires in 10 minutes.`}
        </Text>

        {stage === 'phone' ? (
          <Input
            label="Mobile number"
            prefix="+91"
            placeholder="9876543210"
            keyboardType="number-pad"
            maxLength={10}
            autoComplete="tel"
            textContentType="telephoneNumber"
            value={phone}
            // Stripped on the way in, not merely validated on the way out: a
            // number pasted from Contacts arrives as "+91 98765 43210", and
            // rejecting a correct number over its formatting is the most
            // irritating failure a form has.
            onChangeText={(text) => setPhone(normalizeIndianMobile(text))}
            error={error ?? undefined}
          />
        ) : (
          <Input
            label="Verification code"
            placeholder="123456"
            keyboardType="number-pad"
            maxLength={6}
            autoComplete="sms-otp"
            textContentType="oneTimeCode"
            value={otp}
            onChangeText={(text) => setOtp(text.replace(/\D/g, ''))}
            error={error ?? undefined}
          />
        )}

        <Button
          label={stage === 'phone' ? 'Send code' : 'Verify and continue'}
          fullWidth
          loading={busy}
          onPress={() => void (stage === 'phone' ? onSendCode() : onVerify())}
        />

        {stage === 'code' ? (
          <Pressable
            className="self-center pt-sm"
            hitSlop={gesture.hitSlop}
            disabled={cooldown > 0 || busy}
            onPress={() => void onResend()}
          >
            <Text variant="callout" tone={cooldown > 0 ? 'muted' : 'accent'}>
              {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
            </Text>
          </Pressable>
        ) : null}

        <Pressable
          className="self-center pt-sm"
          hitSlop={gesture.hitSlop}
          onPress={() => settle(false)}
        >
          <Text variant="footnote" tone="muted">
            Not now
          </Text>
        </Pressable>
      </View>
    </Sheet>
  );
}
