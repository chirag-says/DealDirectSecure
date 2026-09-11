/**
 * Google Sign-In.
 *
 * Two endpoints, and the interesting one is the second.
 *
 * THE LINKING DECISION
 * --------------------
 * When a Google identity arrives for an email that already has a password
 * account, the tempting move is to merge them silently: Google verified the
 * email, so the person owns the inbox, so it must be them.
 *
 * That is wrong here, and specifically wrong in THIS codebase, because
 * registration never verifies email. Neither registerUser nor
 * registerUserDirect ever checks that the person signing up can read the
 * address they typed. So anyone can hold an account under someone else's Gmail.
 *
 * Silent merge turns that into account pre-hijacking: an attacker registers
 * victim@gmail.com with their own password and phone, waits, and when the
 * victim later signs in with Google they are dropped straight into the
 * attacker's account — an account whose password the attacker still knows, and
 * whose contents they can read at leisure. Nothing visible would happen.
 *
 * So: an unlinked password account gets a 409, and linking costs one entry of
 * the existing password. Five seconds for the real owner; impossible for an
 * attacker who is not the real owner.
 *
 * The residual hole — an attacker squatting your email can stop you using
 * Google sign-in, though they still cannot reach your data — is a symptom of
 * unverified registration email, and is fixed there, not here.
 */
import User from "../models/userModel.js";
import UserSession from "../models/UserSession.js";
import bcrypt from "bcryptjs";
import { setSessionCookie } from "../middleware/authUser.js";
import { verifyGoogleIdToken, isGoogleAuthConfigured } from "../services/googleIdentity.js";
import { completeRegistrationSideEffects } from "../services/registrationHooks.js";
import { sanitizeUserResponse } from "./userController.js";

/** Map a verification failure to a response. Never leak which check failed. */
const rejectToken = (res, reason) => {
  if (reason === "NOT_CONFIGURED") {
    return res.status(503).json({
      success: false,
      message: "Google sign-in is not available right now.",
      code: "GOOGLE_NOT_CONFIGURED",
    });
  }
  if (reason === "EMAIL_NOT_VERIFIED") {
    return res.status(401).json({
      success: false,
      message: "This Google account does not have a verified email address.",
      code: "GOOGLE_EMAIL_NOT_VERIFIED",
    });
  }
  return res.status(401).json({
    success: false,
    message: "Google sign-in failed. Please try again.",
    code: "GOOGLE_INVALID_TOKEN",
  });
};

/**
 * Shared gate for an account that already exists, whichever door it came in by.
 * Returns true when it has already written a response.
 */
const rejectIfUnusable = (res, user) => {
  if (user.isBlocked) {
    res.status(403).json({
      success: false,
      message: "Your account has been blocked. Contact support.",
      code: "ACCOUNT_BLOCKED",
      blockReason: user.blockReason || "No reason provided",
    });
    return true;
  }
  return false;
};

const issueSession = async (req, res, user, { status = 200, message }) => {
  await user.updateLastLogin(req.ip);
  const { sessionToken } = await UserSession.createSession(user, req);
  setSessionCookie(res, sessionToken);
  return res.status(status).json({ success: true, message, user: sanitizeUserResponse(user) });
};

/**
 * POST /api/users/auth/google
 * Body: { idToken, referralCode? }
 */
export const googleSignIn = async (req, res) => {
  try {
    if (!isGoogleAuthConfigured()) {
      return rejectToken(res, "NOT_CONFIGURED");
    }

    const { idToken, referralCode } = req.body;
    const result = await verifyGoogleIdToken(idToken);
    if (!result.ok) return rejectToken(res, result.reason);

    const { googleId, email, name, picture } = result.identity;

    // Match on `sub` FIRST. A Workspace admin can hand someone else the email
    // address, but the sub belongs to the Google account for its lifetime, so
    // this is the only lookup that is guaranteed to find the right person.
    let user = await User.findOne({ googleId }).select("+blockReason");

    if (user) {
      if (rejectIfUnusable(res, user)) return;

      // Google is authoritative for the address. If it changed upstream, follow
      // it — unless some other local account already holds the new address, in
      // which case leave ours alone rather than collide on a unique index.
      if (user.email !== email) {
        const taken = await User.exists({ email, _id: { $ne: user._id } });
        if (!taken) {
          user.email = email;
          await user.save();
        } else {
          console.warn(
            `[GoogleAuth] sub ${googleId} now reports ${email}, which another account holds. Keeping ${user.email}.`
          );
        }
      }

      console.log(`[GoogleAuth] Sign-in for existing Google account ${user._id}`);
      return issueSession(req, res, user, { message: "Login successful" });
    }

    // No account for this sub. Is there one for the address?
    const byEmail = await User.findOne({ email }).select("+googleId +blockReason");

    if (byEmail) {
      if (rejectIfUnusable(res, byEmail)) return;

      // An account with a DIFFERENT googleId on the same email should not exist
      // — the unique index prevents two accounts sharing a sub, and the email
      // is unique too — but if it somehow does, refusing is the only safe move.
      if (byEmail.googleId && byEmail.googleId !== googleId) {
        console.error(
          `[GoogleAuth] SECURITY: ${email} is linked to sub ${byEmail.googleId} but sub ${googleId} presented a valid token`
        );
        return rejectToken(res, "INVALID_TOKEN");
      }

      // The pre-hijacking case. No session is issued here, deliberately.
      console.log(`[GoogleAuth] Link required for existing password account ${byEmail._id}`);
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists. Enter its password to connect Google.",
        code: "GOOGLE_LINK_REQUIRED",
        email,
      });
    }

    // Brand new account. No password: the schema makes it conditional on
    // googleId being absent. No phone either — that arrives later, and only if
    // the user does something that needs one.
    user = await User.create({
      name: name || email.split("@")[0],
      email,
      googleId,
      profileImage: picture || undefined,
      role: "user",
      isVerified: true,
      emailVerified: true,
      phoneVerified: false,
    });

    await completeRegistrationSideEffects(user, { referralCode });

    console.log(`[GoogleAuth] Created account ${user._id} via Google`);
    return issueSession(req, res, user, { status: 201, message: "Welcome to DealDirect." });
  } catch (err) {
    console.error("[GoogleAuth] Sign-in error:", err);
    return res.status(500).json({ success: false, message: "Google sign-in failed. Please try again." });
  }
};

/**
 * POST /api/users/auth/google/link
 * Body: { idToken, password }
 *
 * The second half of the 409 above. Proving the existing password proves the
 * account is yours; the verified Google token proves the inbox is yours. Both
 * together are what authorise the link.
 */
export const googleLinkAccount = async (req, res) => {
  try {
    if (!isGoogleAuthConfigured()) {
      return rejectToken(res, "NOT_CONFIGURED");
    }

    const { idToken, password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: "Password is required" });
    }

    const result = await verifyGoogleIdToken(idToken);
    if (!result.ok) return rejectToken(res, result.reason);

    const { googleId, email } = result.identity;

    const user = await User.findOne({ email }).select(
      "+password +googleId +security.failedLoginAttempts +security.lockoutUntil +blockReason"
    );

    // Same opaque answer whether the account is missing or the password is
    // wrong, so this endpoint cannot be used to enumerate registered emails.
    if (!user || !user.password) {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    if (user.isLocked()) {
      const remainingMinutes = Math.ceil((user.security.lockoutUntil - Date.now()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMinutes} minutes.`,
        code: "ACCOUNT_LOCKED",
        lockoutUntil: user.security.lockoutUntil,
      });
    }

    if (rejectIfUnusable(res, user)) return;

    // Shares the lockout counter with password login on purpose. Without that,
    // this endpoint would be an unthrottled oracle for guessing the very
    // password that loginUser rate-limits.
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await user.incrementFailedLogins();
      console.warn(`[GoogleAuth] Failed link attempt for ${user._id}`);
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    if (user.googleId && user.googleId !== googleId) {
      return res.status(409).json({
        success: false,
        message: "This account is already connected to a different Google account.",
        code: "GOOGLE_ALREADY_LINKED",
      });
    }

    user.googleId = googleId;
    user.emailVerified = true; // Google has now actually checked the inbox.
    await user.resetFailedLogins();
    await user.save();

    console.log(`[GoogleAuth] Linked Google to existing account ${user._id}`);
    return issueSession(req, res, user, { message: "Google connected. You are signed in." });
  } catch (err) {
    console.error("[GoogleAuth] Link error:", err);
    return res.status(500).json({ success: false, message: "Could not connect Google. Please try again." });
  }
};
