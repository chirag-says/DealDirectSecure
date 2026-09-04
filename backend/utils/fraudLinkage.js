import mongoose from "mongoose";

/**
 * Linkage and velocity checks for a verified close (Phase 3, F15).
 *
 * The pay-both-sides close is the textbook collusion shape: one person with
 * two accounts "sells" to themself. Nothing here decides anything; it
 * produces FLAGS, and the flags do two things: extend the payout hold, and
 * appear on the admin's verification screen. Silent holds, never bans.
 *
 * Every check is a plain lookup an admin could repeat by hand:
 *
 *   same_device         the two accounts registered the same device hash
 *   same_phone          same phone number on both accounts
 *   same_ip             both accounts last signed in from one address
 *   young_account       either account is younger than 14 days at close
 *   first_action_close  the buyer's only ever enquiry is this property
 *   owner_velocity      this owner's third or later close this quarter
 *   attestation_missing the buyer never attested to the close
 *   attestation_dispute the buyer disputed the close
 */

const YOUNG_ACCOUNT_DAYS = 14;
const OWNER_CLOSES_PER_QUARTER = 3;

function quarterStart(date) {
  const q = Math.floor(date.getUTCMonth() / 3) * 3;
  return new Date(Date.UTC(date.getUTCFullYear(), q, 1));
}

/**
 * @param {object} args
 * @param {object} args.verification  the TransactionVerification (owner, buyer, property, attestations)
 * @param {Date}   [args.now]
 * @returns {Promise<string[]>} flags, empty when clean
 */
export async function linkageFlags({ verification, now = new Date() }) {
  const User = mongoose.model("User");
  const Lead = mongoose.model("Lead");
  const TransactionVerification = mongoose.model("TransactionVerification");

  const [owner, buyer] = await Promise.all([
    User.findById(verification.owner).select("+deviceHashes +security.lastLoginIp phone createdAt").lean(),
    User.findById(verification.buyer).select("+deviceHashes +security.lastLoginIp phone createdAt").lean(),
  ]);
  if (!owner || !buyer) return ["party_missing"];

  const flags = [];

  const ownerDevices = new Set(owner.deviceHashes || []);
  if ((buyer.deviceHashes || []).some((h) => ownerDevices.has(h))) flags.push("same_device");

  if (owner.phone && buyer.phone && owner.phone === buyer.phone) flags.push("same_phone");

  const oip = owner.security?.lastLoginIp;
  const bip = buyer.security?.lastLoginIp;
  if (oip && bip && oip === bip) flags.push("same_ip");

  const youngCutoff = new Date(now.getTime() - YOUNG_ACCOUNT_DAYS * 86400 * 1000);
  if (new Date(owner.createdAt) > youngCutoff || new Date(buyer.createdAt) > youngCutoff) flags.push("young_account");

  const buyerLeads = await Lead.countDocuments({ user: buyer._id });
  if (buyerLeads <= 1) flags.push("first_action_close");

  const ownerCloses = await TransactionVerification.countDocuments({
    owner: owner._id,
    status: { $in: ["approved", "pending"] },
    createdAt: { $gte: quarterStart(now) },
  });
  if (ownerCloses >= OWNER_CLOSES_PER_QUARTER) flags.push("owner_velocity");

  const buyerAttestation = verification.attestations?.buyer;
  if (!buyerAttestation?.statement) flags.push("attestation_missing");
  else if (buyerAttestation.statement === "dispute") flags.push("attestation_dispute");

  return flags;
}

export const FLAG_DESCRIPTIONS = Object.freeze({
  same_device: "Both accounts have used the same device",
  same_phone: "Both accounts share a phone number",
  same_ip: "Both accounts last signed in from the same address",
  young_account: "One of the accounts is under two weeks old",
  first_action_close: "This is the buyer's only enquiry on the platform",
  owner_velocity: "Third or later close for this owner this quarter",
  attestation_missing: "The buyer has not confirmed the close",
  attestation_dispute: "The buyer disputed the close",
  party_missing: "One of the accounts no longer exists",
});
