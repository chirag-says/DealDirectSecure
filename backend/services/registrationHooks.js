/**
 * Everything that must happen once, after an account first comes into
 * existence, regardless of which door it came through.
 *
 * There were two hand-maintained copies of this block (verifyOtp and
 * registerUserDirect) before Google sign-in threatened to add a third. They had
 * already drifted: one derived the WhatsApp role label from the user, the other
 * hardcoded "Buyer".
 *
 * Every call here is best-effort. A rewards wallet that failed to create, or an
 * admin WhatsApp ping that did not send, must never turn a successful
 * registration into a 500 for the person who just signed up.
 */
import { getOrCreateWallet, createReferralFromCode } from "./rewardService.js";
import { sendNewUserWhatsApp } from "./whatsappService.js";
import { sendWelcomeEmail } from "../utils/emailService.js";

export const completeRegistrationSideEffects = async (user, { referralCode } = {}) => {
  try {
    // The return value is discarded — this only ensures the wallet exists — so
    // there is no reason to hydrate the transaction array.
    await getOrCreateWallet(user._id, { withTransactions: false });

    if (referralCode) {
      await createReferralFromCode(referralCode, user._id);
    }
  } catch (rewardErr) {
    console.error("[Rewards] Post-registration reward error (non-blocking):", rewardErr.message);
  }

  sendNewUserWhatsApp({
    name: user.name,
    email: user.email,
    phone: user.phone || "",
    role: user.role === "owner" ? "Owner" : "Buyer",
  }).catch((err) => console.error("[WhatsApp] New user notification error:", err.message));

  sendWelcomeEmail(user.email, user.name).catch((err) =>
    console.error("[Email] Welcome email error:", err.message)
  );
};
