import mongoose from "mongoose";

import Property from "../models/Property.js";
import Project from "../models/Project.js";
import UnitType from "../models/UnitType.js";
import Builder from "../models/Builder.js";
import TransactionVerification from "../models/TransactionVerification.js";
import Agreement from "../models/Agreement.js";
import PushToken from "../models/PushToken.js";
import OutboundLog from "../models/OutboundLog.js";
import { Event } from "../models/Event.js";

import { deletePropertyAssets } from "./propertyAssets.js";
import {
  assertUnitTypeDeletable, assertProjectDeletable, DeleteBlockedError,
} from "./deleteGuard.js";

/**
 * Named deletion functions, one per aggregate root.
 *
 * Deliberately five specific functions rather than one generic helper. A
 * `deleteAnything(model, id)` cannot express "a project refuses when unit types
 * exist but a builder deactivates instead of deleting", and hiding those rules
 * behind a shared signature is how they drift apart. These are greppable: if
 * someone asks "what happens when a property is deleted", the answer is one
 * function, not four call sites that had each grown their own version.
 *
 * WHY THE CONSOLIDATION WAS NEEDED
 *
 * Property had two independent delete paths, `deleteProperty` (admin) and
 * `deleteMyProperty` (owner), each with its own copy of the asset cleanup and
 * NEITHER with any dependency check. A third path, the bulk
 * `Property.deleteMany({ owner })` inside account deletion, had no per-property
 * check at all. Deleting a property with a pending TransactionVerification
 * orphaned it, after which admin approve and reject both throw and the buyer's
 * reward becomes permanently unclaimable.
 *
 * ORDERING: refuse before destroying, always.
 *
 * Every function checks its dependents before it touches anything, including
 * before Cloudinary. A refusal that fires after the images are gone is not a
 * refusal, and Cloudinary deletion is not reversible.
 *
 * WHAT IS NOT HERE
 *
 * No deletion policy is invented. The user cascade keeps exactly the twelve
 * collections it already deleted and the six it already retained; changing
 * that split needs the product and legal decision recorded in
 * DEALDIRECT-DELETION-AND-RBAC-DECISION.md §1.6.
 */

/** Agreement states that still bind the parties. Terminal ones do not block. */
const AGREEMENT_TERMINAL = ["cancelled", "terminated", "expired", "draft"];

// ---------------------------------------------------------------------------
// Property
// ---------------------------------------------------------------------------

/**
 * Refuse deleting a property whose deletion would destroy deal or legal
 * evidence.
 *
 * A pending verification is the sharpest case: orphaning it leaves an admin
 * unable to approve OR reject, because both handlers populate the property, and
 * the buyer's reward can then never be claimed. An approved one is the record
 * that the sale happened. A signed agreement is a document with HMAC signatures
 * from two parties.
 *
 * Leads are NOT checked here. They are retained rather than protected: the
 * existing behaviour keeps them (they belong to the owner's pipeline) and this
 * change does not alter it. Anonymising them is the parked decision.
 */
export async function assertPropertyDeletable(propertyId) {
  const blockers = [];

  const verifications = await TransactionVerification.find(
    { property: propertyId, status: { $in: ["pending", "approved"] } },
    { status: 1 }
  ).lean();

  const pending = verifications.filter((v) => v.status === "pending").length;
  const approved = verifications.filter((v) => v.status === "approved").length;

  if (pending) {
    blockers.push(
      `${pending} pending deal verification${pending === 1 ? "" : "s"} would be orphaned ` +
      `(admin approve and reject both break, and the reward becomes unclaimable)`
    );
  }
  if (approved) {
    blockers.push(`${approved} approved deal verification${approved === 1 ? "" : "s"} record a completed sale`);
  }

  const agreements = await Agreement.countDocuments({
    property: propertyId,
    status: { $nin: AGREEMENT_TERMINAL },
  });
  if (agreements) {
    blockers.push(`${agreements} signed agreement${agreements === 1 ? " is" : "s are"} still binding`);
  }

  if (blockers.length) throw new DeleteBlockedError(blockers);
}

/**
 * Delete one property: refuse, then destroy assets, then the document.
 *
 * Replaces two divergent inline copies. Returns the asset-cleanup result so
 * callers can log what actually happened to the images.
 */
export async function deletePropertyAggregate(property) {
  await assertPropertyDeletable(property._id);

  // Only after the refusal. Cloudinary deletion cannot be undone.
  const assets = await deletePropertyAssets(property);
  await Property.deleteOne({ _id: property._id });

  return { propertyId: property._id, assets };
}

// ---------------------------------------------------------------------------
// UnitType
// ---------------------------------------------------------------------------

/**
 * Delete a unit type, keeping the a1651e9 refusals and the counter maintenance
 * that already existed on the controller path.
 *
 * `recalcPriceRange` is injected because it lives in the controller and depends
 * on an aggregation there; passing it keeps the import direction one-way.
 */
export async function deleteUnitTypeAggregate(unitTypeId, { recalcPriceRange } = {}) {
  const unitType = await UnitType.findById(unitTypeId);
  if (!unitType) return null;

  await assertUnitTypeDeletable(unitType._id);

  const projectId = unitType.project;
  await unitType.deleteOne();

  await Project.findByIdAndUpdate(projectId, { $inc: { unitTypeCount: -1 } });
  if (recalcPriceRange) await recalcPriceRange(projectId);

  return { unitTypeId: unitType._id, projectId };
}

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

/**
 * Delete a project.
 *
 * The unit-type check keeps its own 400 and its own message: it predates this
 * consolidation, it is already specific, and changing a status code is a
 * client-visible change this work does not need to make. The booking check
 * from a1651e9 is a 409, as it was.
 */
export async function deleteProjectAggregate(projectId) {
  const project = await Project.findById(projectId);
  if (!project) return null;

  const unitTypeCount = await UnitType.countDocuments({ project: project._id });
  if (unitTypeCount > 0) {
    const err = new Error(
      `Cannot delete project with ${unitTypeCount} unit type(s). Remove unit types first.`
    );
    err.code = "DELETE_BLOCKED_UNIT_TYPES";
    err.status = 400;
    throw err;
  }

  await assertProjectDeletable(project._id);
  await project.deleteOne();

  return { projectId: project._id };
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/**
 * Deactivate a builder. NOT a delete, and that is the existing behaviour.
 *
 * A builder is soft-deleted because the whole chain below it — projects, unit
 * types, campaigns, paid members, bookings — hangs off the reference. The name
 * says "aggregate" for consistency with its siblings; what it actually does is
 * set `isActive = false` after refusing while approved properties exist.
 */
export async function deleteBuilderAggregate(builderId) {
  const builder = await Builder.findById(builderId);
  if (!builder) return null;

  const activePropertyCount = await Property.countDocuments({
    builder: builder._id,
    isApproved: true,
  });

  if (activePropertyCount > 0) {
    const err = new Error(
      `Cannot deactivate builder — they have ${activePropertyCount} active approved ` +
      `propert${activePropertyCount === 1 ? "y" : "ies"}. Disapprove properties first.`
    );
    err.code = "DELETE_BLOCKED_PROPERTIES";
    err.status = 400;
    throw err;
  }

  builder.isActive = false;
  await builder.save();

  return { builderId: builder._id, deactivated: true };
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

/**
 * Collections the account cascade deletes, and the ones it deliberately keeps.
 *
 * Exported so tests can assert the split rather than restating it, and so the
 * decision boundary is one greppable list instead of a comment.
 *
 * ============================ DECISION BOUNDARY ============================
 * RETAINED is NOT a settled policy. Every collection below references the user
 * but also belongs to a counterparty or to a financial or legal record, so
 * deleting it would destroy someone else's data. They are currently kept whole,
 * including the user's name, email and phone in snapshot fields, with no
 * retention period.
 *
 * TODO, each blocked on the product and legal decision in
 * DEALDIRECT-DELETION-AND-RBAC-DECISION.md §1.6 — do not resolve any of these
 * in code without it:
 *
 *   Lead                    → anonymise (snapshot field exists for exactly this)
 *   CampaignMember          → anonymise, keeping the payment fields as evidence
 *   Agreement               → retain (HMAC-signed, two-party, provability is the point)
 *   TransactionVerification → retain (deal proof; also gates reward claims)
 *   ProjectBooking          → retain (UTR + screenshot; `required` client fields)
 *   Reward                  → currently DELETED; a ledger arguably should not be
 *   Referral                → currently DELETED, which removes the other party's credit
 *   Report                  → currently DELETED, letting a reported party erase a complaint
 *   Message                 → currently DELETED, leaving the other side a gapped thread
 *
 * A retention period is also unset. "Retain" without a clock means "keep
 * forever", which is a different policy than anyone intends.
 * ==========================================================================
 */
export const USER_CASCADE = Object.freeze({
  deleted: Object.freeze([
    "Property", "UserSession", "PasswordResetToken",
    "ContactInquiry", "SavedSearch", "Report", "Notification",
    "Message", "Conversation", "Reward", "Referral",
    // Phase 0 additions. A deleted account must stop receiving pushes at
    // once, and its usage rows and outbound log are personal data.
    "PushToken", "OutboundLog", "Event",
  ]),
  retained: Object.freeze([
    "Lead", "Agreement", "TransactionVerification", "CampaignMember", "ProjectBooking",
  ]),
});

/**
 * The account-deletion cascade, moved verbatim from `deleteAccount`.
 *
 * Behaviour is deliberately unchanged: the same twelve collections are deleted,
 * in the same order, with the same field names — four of which were wrong once
 * and silently matched nothing, so they are worth stating explicitly rather
 * than inferring. When adding a collection here, verify the field against the
 * model.
 *
 * Property deletion goes through the per-property guard, which is the one real
 * behavioural consequence of the consolidation: an account holding a property
 * with a pending verification or a live agreement can no longer silently
 * destroy it. Those properties are skipped and reported, so the caller can tell
 * the user what was kept, rather than the delete failing halfway with some
 * collections already gone.
 */
export async function deleteUserAggregate(userId, models) {
  const {
    Property: P, UserSession, PasswordResetToken, ContactInquiry,
    SavedSearch, Report, Notification, Message, Conversation, Reward, Referral, User,
  } = models;

  // 1. Owned properties, and their Cloudinary assets. Each goes through the
  //    aggregate guard, so protected listings survive rather than vanishing.
  const owned = await P.find({ owner: userId }).select("_id images categorizedImages").lean();
  const skipped = [];
  for (const property of owned) {
    try {
      await deletePropertyAggregate(property);
    } catch (err) {
      if (err instanceof DeleteBlockedError) {
        skipped.push({ propertyId: property._id, blockers: err.blockers });
        continue;
      }
      throw err;
    }
  }

  // 2. Sessions and tokens
  await UserSession.deleteMany({ user: userId });
  await PasswordResetToken.deleteMany({ user: userId });
  await PushToken.deleteMany({ user: userId });
  await OutboundLog.deleteMany({ user: userId });
  await Event.deleteMany({ user: userId });

  // 3. Communications and history
  await ContactInquiry.deleteMany({ user: userId });
  await SavedSearch.deleteMany({ user: userId });
  await Report.deleteMany({ reportedBy: userId });
  await Notification.deleteMany({ user: userId });

  // 4. Chat
  await Message.deleteMany({ sender: userId });
  await Conversation.updateMany({ participants: userId }, { $pull: { participants: userId } });
  await Conversation.deleteMany({ participants: { $size: 0 } });

  // 5. Rewards and referrals
  await Reward.deleteMany({ user: userId });
  await Referral.deleteMany({ $or: [{ referrer: userId }, { referred: userId }] });

  // 6. The user. See USER_CASCADE for what is deliberately left standing.
  const deletedUser = await User.findByIdAndDelete(userId);

  return { deletedUser, skippedProperties: skipped };
}

export { DeleteBlockedError };
