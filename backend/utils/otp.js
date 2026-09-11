/**
 * OTP generation, hashing and verification.
 *
 * Extracted verbatim from userController.js, which is no longer the only place
 * that needs them: the just-in-time phone link verifies OTPs too, and a second
 * hand-rolled copy of a hash-and-compare is exactly the kind of duplication
 * that drifts apart and leaves one of the two without the constant-time
 * compare.
 *
 * Behaviour is unchanged. The same OTP_SECRET produces the same hashes, so
 * codes issued before this extraction still verify after it.
 */
import crypto from "crypto";

/** Cryptographically secure 6-digit OTP. */
export const generateSecureOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

/**
 * Hash an OTP for storage, so a database dump does not hand over live codes.
 *
 * Unsalted SHA-256 is adequate here and bcrypt is not: the input is a 6-digit
 * number, so a per-code salt buys nothing against an attacker who can simply
 * enumerate all 900k inputs. What actually protects the code is the secret
 * mixed in below, plus the 10-minute expiry and the attempt cap at the call
 * site.
 */
export const hashOTP = (otp) => {
  const secret = process.env.OTP_SECRET || process.env.JWT_SECRET;
  return crypto.createHash("sha256").update(otp + secret).digest("hex");
};

/** Compare a submitted OTP against a stored hash in constant time. */
export const verifyOTPHash = (providedOtp, storedHash) => {
  const providedHash = hashOTP(providedOtp);
  try {
    return crypto.timingSafeEqual(Buffer.from(providedHash), Buffer.from(storedHash));
  } catch {
    // Thrown when storedHash is absent or a different length. Both mean "no
    // valid OTP on file", which is a failed verification, not an error.
    return false;
  }
};
