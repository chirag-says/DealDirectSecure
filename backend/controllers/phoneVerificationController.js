/**
 * Just-in-time phone verification.
 *
 * The SMS OTP used to be a toll gate on registration. It now fires at the
 * moment an account first attempts something that needs a real person behind a
 * real number: listing a property, expressing interest, closing a deal, signing
 * an agreement, claiming a reward.
 *
 * WHY THE HARDENING BELOW IS NOT OPTIONAL
 * ---------------------------------------
 * Moving the OTP here promotes it from "one speed bump during signup" to the
 * single control standing between an account and every high-value action on the
 * platform. The existing registration OTP has no attempt limit and no send
 * limit, which was survivable when it only guarded signup. It is not survivable
 * now: six digits with unlimited guesses inside a ten-minute window is roughly
 * 900,000 tries against a target that answers instantly, and an authenticated
 * endpoint that dials arbitrary numbers with no cap is an SMS-pumping bill.
 *
 * So this module caps guesses (MAX_ATTEMPTS), caps sends per rolling window
 * (MAX_SENDS_PER_WINDOW), and keeps its state in `user.pendingPhone` rather
 * than the shared `user.otp` field that registration, the owner upgrade and
 * password reset all write to and would clobber.
 */
import User from "../models/userModel.js";
import { sendOtpSms, isSmsConfigured } from "../services/smsService.js";
import { generateSecureOTP, hashOTP, verifyOTPHash } from "../utils/otp.js";
import { sanitizeUserResponse } from "./userController.js";

const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes, matching registration
const MAX_ATTEMPTS = 5;
const SEND_WINDOW_MS = 15 * 60 * 1000;
const MAX_SENDS_PER_WINDOW = 3;

const PHONE_REGEX = /^[6-9]\d{9}$/;

/** Select string for the pendingPhone subdocument, which is hidden by default. */
const PENDING = "+pendingPhone.phone +pendingPhone.otp +pendingPhone.expires +pendingPhone.attempts +pendingPhone.sends +pendingPhone.windowStart";

/**
 * POST /api/users/phone/send-otp
 * Body: { phone }
 * Auth required.
 */
export const sendPhoneOtp = async (req, res) => {
  try {
    const phone = (req.body?.phone || "").toString().trim();

    if (!PHONE_REGEX.test(phone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 10-digit mobile number.",
        code: "INVALID_PHONE",
      });
    }

    if (!isSmsConfigured()) {
      console.error("[PhoneVerify] SMS service is not configured");
      return res.status(503).json({
        success: false,
        message: "Verification is unavailable right now. Please try again later.",
        code: "SMS_NOT_CONFIGURED",
      });
    }

    const user = await User.findById(req.user._id).select(PENDING);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.phoneVerified && user.phone === phone) {
      return res.status(200).json({
        success: true,
        message: "This number is already verified.",
        alreadyVerified: true,
      });
    }

    // The number must not belong to anyone else. Refusing rather than merging
    // is deliberate: `phone` is a unique index, and quietly moving a verified
    // number between accounts is how two people end up sharing one identity.
    const takenBy = await User.exists({ phone, _id: { $ne: user._id } });
    if (takenBy) {
      console.warn(`[PhoneVerify] User ${user._id} tried to claim phone held by another account`);
      return res.status(409).json({
        success: false,
        message: "This number is already linked to another DealDirect account.",
        code: "PHONE_ALREADY_LINKED",
      });
    }

    // Rolling send window, per account. Every send costs real money at Equence
    // and rings a real handset, so the cap protects both the bill and whoever
    // owns the number being dialled.
    const now = Date.now();
    const windowStart = user.pendingPhone?.windowStart?.getTime() ?? 0;
    const windowExpired = now - windowStart > SEND_WINDOW_MS;
    const sends = windowExpired ? 0 : user.pendingPhone?.sends ?? 0;

    if (sends >= MAX_SENDS_PER_WINDOW) {
      const retryAfterSec = Math.ceil((windowStart + SEND_WINDOW_MS - now) / 1000);
      return res.status(429).json({
        success: false,
        message: "Too many verification codes requested. Please try again shortly.",
        code: "OTP_SEND_LIMIT",
        retryAfter: retryAfterSec,
      });
    }

    const otp = generateSecureOTP();

    user.pendingPhone = {
      phone,
      otp: hashOTP(otp),
      expires: new Date(now + OTP_TTL_MS),
      attempts: 0, // A fresh code gets a fresh budget of guesses.
      sends: sends + 1,
      windowStart: windowExpired ? new Date(now) : user.pendingPhone.windowStart,
    };
    await user.save();

    const smsResult = await sendOtpSms(phone, otp, user.name);
    if (!smsResult.success) {
      console.error("[PhoneVerify] SMS send failed:", smsResult.error);
      return res.status(502).json({
        success: false,
        message: "Could not send the verification code. Please try again.",
        code: "SMS_SEND_FAILED",
      });
    }

    console.log(`[PhoneVerify] OTP sent for user ${user._id}`);
    return res.status(200).json({
      success: true,
      message: "Verification code sent.",
      // Last two digits only, so the UI can say "ending 47" without this
      // endpoint becoming a way to read back a number you guessed.
      phoneHint: phone.slice(-2),
      expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    });
  } catch (err) {
    console.error("[PhoneVerify] send-otp error:", err);
    return res.status(500).json({ success: false, message: "Could not send the verification code." });
  }
};

/**
 * POST /api/users/phone/verify-otp
 * Body: { otp }
 * Auth required.
 */
export const verifyPhoneOtp = async (req, res) => {
  try {
    const otp = (req.body?.otp || "").toString().trim();

    if (!otp) {
      return res.status(400).json({ success: false, message: "Enter the verification code." });
    }

    const user = await User.findById(req.user._id).select(PENDING);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const pending = user.pendingPhone;

    if (!pending?.otp || !pending?.phone || !pending?.expires || pending.expires < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "This code has expired. Request a new one.",
        code: "OTP_EXPIRED",
      });
    }

    // Attempt cap. Without it the six-digit code is not a control, just a delay.
    if ((pending.attempts ?? 0) >= MAX_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: "Too many incorrect attempts. Request a new code.",
        code: "OTP_ATTEMPTS_EXCEEDED",
      });
    }

    if (!verifyOTPHash(otp, pending.otp)) {
      user.pendingPhone.attempts = (pending.attempts ?? 0) + 1;
      const remaining = MAX_ATTEMPTS - user.pendingPhone.attempts;

      // Burn the code on the final miss rather than leaving it alive until it
      // expires: a code that has survived five wrong guesses should not still
      // be guessable for the rest of the window.
      if (remaining <= 0) {
        user.pendingPhone.otp = undefined;
        user.pendingPhone.expires = undefined;
      }
      await user.save();

      console.warn(`[PhoneVerify] Wrong OTP for user ${user._id} (${user.pendingPhone.attempts}/${MAX_ATTEMPTS})`);
      return res.status(400).json({
        success: false,
        message: "Incorrect code.",
        code: "OTP_INVALID",
        attemptsRemaining: Math.max(remaining, 0),
      });
    }

    // Re-check the uniqueness claim. The number was free when the code was
    // sent, but that was up to ten minutes ago and someone else may have
    // verified it since. The unique index would reject the save anyway; this
    // turns a 500 into an explanation.
    const takenBy = await User.exists({ phone: pending.phone, _id: { $ne: user._id } });
    if (takenBy) {
      user.pendingPhone = undefined;
      await user.save();
      return res.status(409).json({
        success: false,
        message: "This number is already linked to another DealDirect account.",
        code: "PHONE_ALREADY_LINKED",
      });
    }

    user.phone = pending.phone;
    user.phoneVerified = true;
    user.phoneVerifiedAt = new Date();
    user.pendingPhone = undefined;
    await user.save();

    console.log(`[PhoneVerify] Phone linked and verified for user ${user._id}`);
    return res.status(200).json({
      success: true,
      message: "Mobile number verified.",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    // A duplicate-key error here means the number was claimed between the check
    // above and this save. Rare, but it is a race, not a bug in the caller.
    if (err?.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "This number is already linked to another DealDirect account.",
        code: "PHONE_ALREADY_LINKED",
      });
    }
    console.error("[PhoneVerify] verify-otp error:", err);
    return res.status(500).json({ success: false, message: "Verification failed. Please try again." });
  }
};

/**
 * GET /api/users/phone/status
 * Auth required. Lets a client that is resuming mid-flow decide what to show
 * without guessing from a stale cached user object.
 */
export const getPhoneStatus = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select(PENDING);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const pending = user.pendingPhone;
    const hasLiveOtp = !!(pending?.otp && pending?.expires && pending.expires > Date.now());

    return res.status(200).json({
      success: true,
      phoneVerified: !!user.phoneVerified,
      phone: user.phoneVerified ? user.phone : null,
      pendingPhoneHint: hasLiveOtp ? pending.phone.slice(-2) : null,
      attemptsRemaining: hasLiveOtp ? Math.max(MAX_ATTEMPTS - (pending.attempts ?? 0), 0) : null,
    });
  } catch (err) {
    console.error("[PhoneVerify] status error:", err);
    return res.status(500).json({ success: false, message: "Could not read verification status." });
  }
};
