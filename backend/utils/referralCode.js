import crypto from "crypto";
import mongoose from "mongoose";

/**
 * Referral code generation, in one place (Phase 5, F21).
 *
 * This was written inline inside `getUserReferralCode`, which was fine while
 * exactly one screen minted codes. The reward-claim moment now mints them too
 * — the research puts the invitation right after the reward reveal — and two
 * copies of a uniqueness loop is how two formats end up in one column.
 *
 * `DD` plus four characters from an unambiguous alphabet: no O/0 or I/1
 * confusion, because these get read aloud and typed from a screenshot.
 * Collisions are retried against the unique index rather than trusted to
 * probability.
 */

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const LENGTH = 4;
const MAX_ATTEMPTS = 10;

export function randomReferralCode() {
  let code = "DD";
  for (let i = 0; i < LENGTH; i += 1) {
    code += ALPHABET.charAt(crypto.randomInt(0, ALPHABET.length));
  }
  return code;
}

/**
 * A code no other account holds, or null after `MAX_ATTEMPTS`.
 *
 * Null rather than a throw: a referral code is a nicety, and no caller
 * should fail a reward claim or a wallet read because the dice were unkind
 * ten times in a row.
 */
export async function generateReferralCode() {
  const User = mongoose.model("User");
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const code = randomReferralCode();
    const existing = await User.findOne({ referralCode: code }).select("_id").lean();
    if (!existing) return code;
  }
  console.error("[referral] could not find a free code in", MAX_ATTEMPTS, "attempts");
  return null;
}
