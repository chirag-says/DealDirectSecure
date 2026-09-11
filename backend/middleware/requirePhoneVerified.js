/**
 * The just-in-time phone gate, and the owner promotion that rides with it.
 *
 * Registration no longer collects a phone number or asks whether you are a
 * buyer or an owner. Both facts are established later, at the first moment they
 * actually matter, which is what these two middlewares enforce.
 */
import User from "../models/userModel.js";

/**
 * Block an action until the account has a verified mobile number.
 *
 * Mount AFTER authMiddleware. The 403 body is a contract: both clients open
 * their verification sheet on `code === "PHONE_VERIFICATION_REQUIRED"` and
 * replay the original request once it succeeds, so the code must not change
 * without changing them.
 */
export const requirePhoneVerified = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
      code: "NOT_AUTHENTICATED",
    });
  }

  // Deliberately reads phoneVerified, never isVerified. isVerified means only
  // "this account is usable" — registerUserDirect sets it at creation without
  // proving anything at all — so trusting it here would leave the gate open.
  if (!req.user.phoneVerified) {
    return res.status(403).json({
      success: false,
      message: "Verify your mobile number to continue.",
      code: "PHONE_VERIFICATION_REQUIRED",
    });
  }

  next();
};

/**
 * Promote a buyer to owner at the moment they first list a property.
 *
 * Role used to be declared on the signup form. With one registration flow there
 * is nothing to declare, so the role is derived from what the account actually
 * does. The client never sends a role and is never asked for one.
 *
 * Mount AFTER requirePhoneVerified: the phone check is what makes the promotion
 * safe to grant, so granting it first would hand out `owner` for free.
 */
export const ensureOwnerRole = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
        code: "NOT_AUTHENTICATED",
      });
    }

    if (req.user.role === "owner") return next();

    // Belt and braces. The route ordering above already guarantees this, but an
    // unverified promotion is severe enough to be worth refusing twice.
    if (!req.user.phoneVerified) {
      return res.status(403).json({
        success: false,
        message: "Verify your mobile number to continue.",
        code: "PHONE_VERIFICATION_REQUIRED",
      });
    }

    await User.updateOne({ _id: req.user._id }, { $set: { role: "owner" } });
    req.user.role = "owner";

    console.log(`[Role] User ${req.user._id} promoted to owner on first listing`);
    next();
  } catch (err) {
    console.error("[Role] Owner promotion failed:", err);
    return res.status(500).json({
      success: false,
      message: "Could not complete this action. Please try again.",
    });
  }
};
