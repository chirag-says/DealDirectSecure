import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Lead from "../models/Lead.js";
import TransactionVerification from "../models/TransactionVerification.js";
import User from "../models/userModel.js";
import { notifyUser } from "../services/notificationService.js";
import { deriveStage, progressFor, VISIT_OPEN } from "../utils/dealStage.js";
import { assertLeadTransition } from "../utils/leadState.js";
import { awardMilestone } from "../services/rewardService.js";
import { buyerContextsFor } from "../utils/buyerContext.js";
import Review from "../models/Review.js";

/**
 * The deal room (Phase 2, F11 + F12), built on `Lead`.
 *
 * ROLES. A deal has exactly two parties: `lead.user` (buyer) and
 * `lead.propertyOwner` (owner). Every handler resolves the caller to one of
 * them from the database and refuses anyone else; the role is never read
 * from the request. Both parties see the same tracker, visits and
 * conversation; what differs is contact detail (below) and owner-only notes.
 *
 * CONTACT REVEAL. The owner already receives the buyer's name, email and
 * phone with the enquiry; that is what an enquiry is. The buyer sees the
 * owner's phone only once the owner has engaged (`firstOwnerResponseAt`),
 * so a listing owner who never responds is never cold-called from a scraped
 * deal page, and an owner who did respond is reachable without a third
 * party. The rule is stated on the page.
 *
 * STAGE. Never written by a client. `deriveStage` reads the facts and the
 * cached `stage` is refreshed whenever a fact changes (`syncStage`).
 */

const CHAT_ENABLED = () => process.env.CHAT_ENABLED === "true";
const AGREEMENTS_ENABLED = () => process.env.AGREEMENTS_ENABLED === "true";

const MAX_VISIT_DAYS_AHEAD = 60;
const VISIT_DONE_GRACE_MS = 30 * 60 * 1000;

const isId = (v) => mongoose.Types.ObjectId.isValid(v);
const same = (a, b) => a && b && String(a) === String(b);

const PROPERTY_FIELDS = "title price priceUnit listingType city locality address images categorizedImages status owner";

/** Resolve the caller's side of a lead, or null when they are neither party. */
function roleOn(lead, userId) {
  if (same(lead.user, userId)) return "buyer";
  if (same(lead.propertyOwner, userId)) return "owner";
  return null;
}

async function syncStage(lead, now = new Date()) {
  const stage = deriveStage(lead, now);
  if (lead.stage !== stage) {
    lead.stage = stage;
    lead.stageUpdatedAt = now;
  }
  return stage;
}

/** Owner engagement, recorded once. Exported for the chat and lead controllers. */
export async function markOwnerResponded(leadOrId, at = new Date()) {
  const filter = typeof leadOrId === "object" && leadOrId._id ? { _id: leadOrId._id } : { _id: leadOrId };
  await Lead.updateOne({ ...filter, firstOwnerResponseAt: null }, { $set: { firstOwnerResponseAt: at } });
}

function pickVisit(v) {
  return {
    id: v._id,
    scheduledAt: v.scheduledAt,
    status: v.status,
    doneConfirmedBy: v.doneConfirmedBy || [],
    proposedBy: v.proposedBy,
    confirmedBy: v.confirmedBy,
    completedBy: v.completedBy,
    note: v.note || "",
    feedback: v.feedback || null,
    feedbackAt: v.feedbackAt || null,
    createdAt: v.createdAt,
    updatedAt: v.updatedAt,
  };
}

function propertyView(p) {
  if (!p || typeof p !== "object") return null;
  return {
    id: p._id,
    title: p.title,
    price: p.price,
    priceUnit: p.priceUnit,
    listingType: p.listingType,
    city: p.city || p.address?.city || null,
    locality: p.locality || p.address?.area || null,
    image: p.images?.[0] || p.categorizedImages?.exterior?.[0] || null,
    status: p.status,
  };
}

/**
 * The shared view of one deal for one party.
 */
async function buildDealView(lead, role, viewerId, now = new Date()) {
  const stage = await syncStage(lead, now);
  if (lead.isModified()) await lead.save();

  const counterpartId = role === "buyer" ? lead.propertyOwner : lead.user;
  const counterpart = await User.findById(counterpartId).select("name profileImage phone email verification").lean();

  const revealPhone = role === "owner" || !!lead.firstOwnerResponseAt;

  let conversation = null;
  if (CHAT_ENABLED() && lead.conversation) {
    const c = await Conversation.findById(lead.conversation).select("lastMessage unreadCount updatedAt").lean();
    if (c) {
      const unread = c.unreadCount instanceof Map ? c.unreadCount.get(String(viewerId)) : c.unreadCount?.[String(viewerId)];
      conversation = {
        id: c._id,
        unread: unread || 0,
        lastMessage: c.lastMessage?.text
          ? { text: c.lastMessage.text, sender: c.lastMessage.sender, at: c.lastMessage.createdAt }
          : null,
      };
    }
  }

  let verification = null;
  if (lead.verification) {
    const v = await TransactionVerification.findById(lead.verification)
      .select("status closingType ownerClaimed buyerClaimed payoutHoldUntil reviewedAt attestations")
      .lean();
    if (v) {
      const mine = v.attestations?.[role];
      const theirs = v.attestations?.[role === "owner" ? "buyer" : "owner"];
      const [myReview, theirReview] = await Promise.all([
        Review.findOne({ verification: v._id, author: viewerId }).select("status").lean(),
        Review.findOne({ verification: v._id, subject: viewerId }).select("status").lean(),
      ]);
      verification = {
        id: v._id,
        status: v.status,
        closingType: v.closingType,
        claimed: role === "owner" ? !!v.ownerClaimed : !!v.buyerClaimed,
        payoutHoldUntil: v.payoutHoldUntil || null,
        attestation: {
          mine: mine?.statement ? { statement: mine.statement, at: mine.at } : null,
          counterpartDone: !!theirs?.statement,
        },
        review: {
          eligible: v.status === "approved" && !myReview,
          submitted: !!myReview,
          status: myReview?.status || null,
          counterpartSubmitted: !!theirReview,
        },
      };
    }
  }

  let buyerContext;
  if (role === "owner") {
    try {
      const price = lead.property?.price ?? lead.propertySnapshot?.price;
      const contexts = await buyerContextsFor([lead.user], new Map([[String(lead.user), price]]));
      buyerContext = contexts.get(String(lead.user)) || null;
    } catch (ctxErr) {
      console.error("[deals] buyer context failed:", ctxErr.message);
      buyerContext = null;
    }
  }

  return {
    id: lead._id,
    role,
    stage,
    stageUpdatedAt: lead.stageUpdatedAt,
    status: lead.status,
    createdAt: lead.createdAt,
    progress: progressFor(lead, now),
    property: propertyView(lead.property),
    counterpart: counterpart
      ? {
          id: counterpart._id,
          name: counterpart.name,
          profileImage: counterpart.profileImage || null,
          phone: revealPhone ? counterpart.phone || null : null,
          email: role === "owner" ? counterpart.email || null : null,
          verified: !!counterpart.verification?.identity,
        }
      : null,
    contactRevealed: revealPhone,
    firstOwnerResponseAt: lead.firstOwnerResponseAt,
    visits: (lead.visits || []).map(pickVisit),
    conversation,
    chatEnabled: CHAT_ENABLED(),
    agreementsEnabled: AGREEMENTS_ENABLED(),
    agreement: lead.agreement ? { id: lead.agreement, at: lead.agreementAt } : null,
    verification,
    // Owner-only working notes; never shown to the buyer.
    notes: role === "owner" ? lead.notes || "" : undefined,
    userSnapshot: role === "owner" ? lead.userSnapshot : undefined,
    buyerContext,
  };
}

/** Load a lead the caller is party to, or answer the request with the reason. */
async function loadForParty(req, res) {
  const { leadId } = req.params;
  if (!isId(leadId)) {
    res.status(400).json({ success: false, code: "INVALID_ID", message: "Invalid deal id" });
    return null;
  }
  const lead = await Lead.findById(leadId).populate("property", PROPERTY_FIELDS);
  if (!lead) {
    res.status(404).json({ success: false, code: "NOT_FOUND", message: "Deal not found" });
    return null;
  }
  const role = roleOn(lead, req.user._id);
  if (!role) {
    res.status(403).json({ success: false, code: "NOT_A_PARTY", message: "You are not part of this deal" });
    return null;
  }
  return { lead, role };
}

// ---------------------------------------------------------------------------
// GET /deals?role=buyer|owner&stage=...&page=&limit=
// ---------------------------------------------------------------------------
export const listMyDeals = async (req, res) => {
  try {
    const me = req.user._id;
    const role = ["buyer", "owner"].includes(req.query.role) ? req.query.role : null;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));

    const sides = [];
    if (!role || role === "buyer") sides.push({ user: me });
    if (!role || role === "owner") sides.push({ propertyOwner: me });
    const filter = { $or: sides };
    if (req.query.stage && ["contacted", "visit_scheduled", "visited", "agreement", "closed"].includes(req.query.stage)) {
      filter.stage = req.query.stage;
    }

    const [leads, total] = await Promise.all([
      Lead.find(filter)
        .populate("property", PROPERTY_FIELDS)
        .sort({ updatedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Lead.countDocuments(filter),
    ]);

    const now = new Date();
    const conversationIds = leads.map((l) => l.conversation).filter(Boolean);
    const conversations = CHAT_ENABLED() && conversationIds.length
      ? await Conversation.find({ _id: { $in: conversationIds } }).select("unreadCount").lean()
      : [];
    const unreadByConversation = new Map(
      conversations.map((c) => {
        const unread = c.unreadCount instanceof Map ? c.unreadCount.get(String(me)) : c.unreadCount?.[String(me)];
        return [String(c._id), unread || 0];
      })
    );

    const data = [];
    for (const lead of leads) {
      const side = roleOn(lead, me);
      const stage = await syncStage(lead, now);
      if (lead.isModified()) await lead.save();
      const nextVisit = (lead.visits || [])
        .filter((v) => VISIT_OPEN.includes(v.status) && new Date(v.scheduledAt) >= now)
        .sort((a, b) => new Date(a.scheduledAt) - new Date(b.scheduledAt))[0];
      data.push({
        id: lead._id,
        role: side,
        stage,
        status: lead.status,
        property: propertyView(lead.property),
        counterpartName: side === "owner" ? lead.userSnapshot?.name : undefined,
        nextVisit: nextVisit ? pickVisit(nextVisit) : null,
        unread: lead.conversation ? unreadByConversation.get(String(lead.conversation)) || 0 : 0,
        awaitingOwner: side === "owner" && !lead.firstOwnerResponseAt,
        updatedAt: lead.updatedAt,
        createdAt: lead.createdAt,
      });
    }

    res.status(200).json({
      success: true,
      data,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    console.error("[deals] list failed:", error);
    res.status(500).json({ success: false, message: "Could not load your deals" });
  }
};

// ---------------------------------------------------------------------------
// GET /deals/:leadId
// ---------------------------------------------------------------------------
export const getDeal = async (req, res) => {
  try {
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const view = await buildDealView(loaded.lead, loaded.role, req.user._id);
    res.status(200).json({ success: true, data: view });
  } catch (error) {
    console.error("[deals] get failed:", error);
    res.status(500).json({ success: false, message: "Could not load this deal" });
  }
};

// ---------------------------------------------------------------------------
// POST /deals/:leadId/visits   { scheduledAt, note? }
// ---------------------------------------------------------------------------
export const proposeVisit = async (req, res) => {
  try {
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const { lead, role } = loaded;
    const now = new Date();

    if (lead.status === "converted") {
      return res.status(409).json({ success: false, code: "DEAL_CLOSED", message: "This deal is already closed" });
    }

    const scheduledAt = new Date(req.body?.scheduledAt);
    if (Number.isNaN(scheduledAt.getTime())) {
      return res.status(400).json({ success: false, code: "INVALID_TIME", message: "A valid visit time is required" });
    }
    if (scheduledAt.getTime() <= now.getTime()) {
      return res.status(400).json({ success: false, code: "TIME_IN_PAST", message: "Pick a time in the future" });
    }
    if (scheduledAt.getTime() > now.getTime() + MAX_VISIT_DAYS_AHEAD * 86400 * 1000) {
      return res.status(400).json({ success: false, code: "TOO_FAR_AHEAD", message: `Visits can be planned up to ${MAX_VISIT_DAYS_AHEAD} days ahead` });
    }

    const open = (lead.visits || []).find((v) => VISIT_OPEN.includes(v.status) && new Date(v.scheduledAt) >= now);
    if (open) {
      return res.status(409).json({
        success: false,
        code: "VISIT_ALREADY_OPEN",
        message: "There is already a visit planned. Cancel it to propose another time.",
        visitId: open._id,
      });
    }

    const note = typeof req.body?.note === "string" ? req.body.note.trim().slice(0, 200) : "";

    lead.visits.push({ scheduledAt, status: "proposed", proposedBy: req.user._id, note, createdAt: now, updatedAt: now });
    if (role === "owner" && !lead.firstOwnerResponseAt) lead.firstOwnerResponseAt = now;
    await syncStage(lead, now);
    await lead.save();

    const visit = lead.visits[lead.visits.length - 1];
    const counterpart = role === "buyer" ? lead.propertyOwner : lead.user;
    const title = lead.property?.title || "the property";

    await notifyUser(counterpart, {
      title: "Visit proposed",
      message: `${req.user.name} proposed a visit to ${title} on ${formatIst(scheduledAt)}. Confirm if it works for you.`,
      type: "visit_proposed",
      data: { leadId: lead._id, visitId: visit._id, propertyId: lead.property?._id, actionUrl: `/deals/${lead._id}`, actionText: "Review visit" },
    });

    res.status(201).json({ success: true, data: pickVisit(visit), stage: lead.stage });
  } catch (error) {
    console.error("[deals] propose visit failed:", error);
    res.status(500).json({ success: false, message: "Could not propose the visit" });
  }
};

// ---------------------------------------------------------------------------
// PUT /deals/:leadId/visits/:visitId   { action: confirm|cancel|done|no_show }
// ---------------------------------------------------------------------------
export const updateVisit = async (req, res) => {
  try {
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const { lead, role } = loaded;
    const now = new Date();

    const visit = (lead.visits || []).id(req.params.visitId);
    if (!visit) {
      return res.status(404).json({ success: false, code: "VISIT_NOT_FOUND", message: "Visit not found" });
    }

    const action = req.body?.action;
    const counterpart = role === "buyer" ? lead.propertyOwner : lead.user;
    const title = lead.property?.title || "the property";
    let notification = null;

    switch (action) {
      case "confirm": {
        if (visit.status !== "proposed") {
          return res.status(409).json({ success: false, code: "NOT_PROPOSED", message: `A ${visit.status} visit cannot be confirmed` });
        }
        if (same(visit.proposedBy, req.user._id)) {
          return res.status(409).json({ success: false, code: "OWN_PROPOSAL", message: "The other party confirms a visit you proposed" });
        }
        if (new Date(visit.scheduledAt) <= now) {
          return res.status(409).json({ success: false, code: "TIME_PASSED", message: "This time has already passed. Propose a new one." });
        }
        visit.status = "confirmed";
        visit.confirmedBy = req.user._id;
        notification = {
          title: "Visit confirmed",
          message: `${req.user.name} confirmed the visit to ${title} on ${formatIst(visit.scheduledAt)}.`,
          type: "visit_confirmed",
        };
        break;
      }
      case "cancel": {
        if (!VISIT_OPEN.includes(visit.status)) {
          return res.status(409).json({ success: false, code: "NOT_OPEN", message: `A ${visit.status} visit cannot be cancelled` });
        }
        visit.status = "cancelled";
        visit.cancelledBy = req.user._id;
        notification = {
          title: "Visit cancelled",
          message: `${req.user.name} cancelled the visit to ${title} planned for ${formatIst(visit.scheduledAt)}.`,
          type: "visit_cancelled",
        };
        break;
      }
      case "done":
      case "no_show": {
        const alreadyDone = visit.status === "done" && action === "done";
        if (!alreadyDone && !VISIT_OPEN.includes(visit.status)) {
          return res.status(409).json({ success: false, code: "NOT_OPEN", message: `A ${visit.status} visit cannot be marked ${action}` });
        }
        if (new Date(visit.scheduledAt).getTime() - VISIT_DONE_GRACE_MS > now.getTime()) {
          return res.status(409).json({ success: false, code: "TOO_EARLY", message: "The visit has not happened yet" });
        }
        if (alreadyDone) {
          // The second party confirming a visit the first already closed.
          if (visit.doneConfirmedBy.some((id) => same(id, req.user._id))) {
            return res.status(409).json({ success: false, code: "ALREADY_CONFIRMED", message: "You already confirmed this visit" });
          }
          visit.doneConfirmedBy.push(req.user._id);
          break;
        }
        visit.status = action;
        visit.completedBy = req.user._id;
        if (action === "done") visit.doneConfirmedBy = [req.user._id];
        if (action === "done" && role === "owner") {
          // The buyer is asked how it went; the owner sees the answer as a signal.
          notification = {
            title: "How was the visit?",
            message: `You visited ${title}. Two taps tell the owner where you stand.`,
            type: "visit_feedback_request",
            to: lead.user,
          };
        } else if (action === "no_show") {
          notification = {
            title: "Visit marked as no-show",
            message: `${req.user.name} recorded that the visit to ${title} did not happen.`,
            type: "deal_stage",
          };
        }
        break;
      }
      default:
        return res.status(400).json({ success: false, code: "INVALID_ACTION", message: "action must be confirm, cancel, done or no_show" });
    }

    visit.updatedAt = now;
    if (role === "owner" && !lead.firstOwnerResponseAt) lead.firstOwnerResponseAt = now;

    // Phase 3 (F15): both parties marked the visit done. One milestone each,
    // non-cashable, policy-gated inside awardMilestone. Never blocks.
    let milestone = null;
    if (visit.status === "done" && visit.doneConfirmedBy.length >= 2 && !visit.milestoneAwardedAt) {
      visit.milestoneAwardedAt = now;
      const meta = { leadId: lead._id, visitId: visit._id };
      const [mine] = await Promise.all([
        awardMilestone(req.user._id, "visit_completed", meta),
        awardMilestone(role === "buyer" ? lead.propertyOwner : lead.user, "visit_completed", meta),
      ]);
      if (mine?.success && mine.pointsAwarded > 0) milestone = mine;
    }

    await syncStage(lead, now);
    await lead.save();

    if (notification) {
      const { to, ...payload } = notification;
      await notifyUser(to || counterpart, {
        ...payload,
        data: { leadId: lead._id, visitId: visit._id, propertyId: lead.property?._id, actionUrl: `/deals/${lead._id}`, actionText: "Open deal" },
      });
    }

    res.status(200).json({ success: true, data: pickVisit(visit), stage: lead.stage, milestone });
  } catch (error) {
    console.error("[deals] update visit failed:", error);
    res.status(500).json({ success: false, message: "Could not update the visit" });
  }
};

// ---------------------------------------------------------------------------
// POST /deals/:leadId/visits/:visitId/feedback   { feedback }
// ---------------------------------------------------------------------------
const FEEDBACK_TO_STATUS = { interested: "interested", thinking: "contacted", not_interested: "lost" };

export const visitFeedback = async (req, res) => {
  try {
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const { lead, role } = loaded;
    if (role !== "buyer") {
      return res.status(403).json({ success: false, code: "BUYER_ONLY", message: "Only the visitor gives visit feedback" });
    }

    const visit = (lead.visits || []).id(req.params.visitId);
    if (!visit) return res.status(404).json({ success: false, code: "VISIT_NOT_FOUND", message: "Visit not found" });
    if (visit.status !== "done") {
      return res.status(409).json({ success: false, code: "VISIT_NOT_DONE", message: "Feedback is for a visit that happened" });
    }
    if (visit.feedback) {
      return res.status(409).json({ success: false, code: "FEEDBACK_GIVEN", message: "Feedback already recorded" });
    }

    const feedback = req.body?.feedback;
    if (!FEEDBACK_TO_STATUS[feedback]) {
      return res.status(400).json({ success: false, code: "INVALID_FEEDBACK", message: "feedback must be interested, thinking or not_interested" });
    }

    const now = new Date();
    visit.feedback = feedback;
    visit.feedbackAt = now;
    visit.updatedAt = now;

    // The honest signal to the owner: the lead status follows the feedback,
    // but only where the transition table allows it (a converted lead never
    // moves, and only "interested" may move a lead forward past "contacted").
    const target = FEEDBACK_TO_STATUS[feedback];
    try {
      const forward = ["new", "contacted", "interested", "negotiating"];
      const goesBackward = forward.indexOf(target) < forward.indexOf(lead.status) && target !== "lost";
      if (!goesBackward) {
        assertLeadTransition(lead.status, target);
        lead.status = target;
      }
    } catch {
      // illegal transition: keep the status, keep the feedback
    }

    await syncStage(lead, now);
    await lead.save();

    const title = lead.property?.title || "the property";
    const wording = { interested: "is interested", thinking: "is still deciding", not_interested: "is not going ahead" }[feedback];
    await notifyUser(lead.propertyOwner, {
      title: "Visit feedback",
      message: `${req.user.name} ${wording} after visiting ${title}.`,
      type: "deal_stage",
      data: { leadId: lead._id, visitId: visit._id, propertyId: lead.property?._id, actionUrl: `/deals/${lead._id}`, actionText: "Open deal" },
    });

    res.status(200).json({ success: true, data: pickVisit(visit), status: lead.status, stage: lead.stage });
  } catch (error) {
    console.error("[deals] feedback failed:", error);
    res.status(500).json({ success: false, message: "Could not record feedback" });
  }
};

// ---------------------------------------------------------------------------
// POST /deals/:leadId/conversation
// ---------------------------------------------------------------------------
export const openConversation = async (req, res) => {
  try {
    if (!CHAT_ENABLED()) {
      return res.status(503).json({ success: false, code: "CHAT_DISABLED", message: "Messaging is not available right now" });
    }
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const { lead } = loaded;

    if (lead.conversation) {
      const existing = await Conversation.findById(lead.conversation).select("_id").lean();
      if (existing) return res.status(200).json({ success: true, data: { conversationId: existing._id }, isNew: false });
    }

    const propertyId = lead.property?._id || lead.property;
    const buyer = String(lead.user);
    const owner = String(lead.propertyOwner);

    let conversation = await Conversation.findOne({ participants: { $all: [buyer, owner] }, property: propertyId });
    let isNew = false;
    if (!conversation) {
      conversation = await Conversation.create({
        participants: [buyer, owner],
        property: propertyId,
        unreadCount: { [buyer]: 0, [owner]: 0 },
      });
      isNew = true;
    }

    lead.conversation = conversation._id;
    await lead.save();

    res.status(isNew ? 201 : 200).json({ success: true, data: { conversationId: conversation._id }, isNew });
  } catch (error) {
    console.error("[deals] open conversation failed:", error);
    res.status(500).json({ success: false, message: "Could not open messaging" });
  }
};

// ---------------------------------------------------------------------------
// Helpers shared with other controllers
// ---------------------------------------------------------------------------

/** Find the lead behind a conversation, if there is one. */
export async function leadForConversation(conversationId) {
  return Lead.findOne({ conversation: conversationId });
}

/** Find the lead an agreement is attached to, if any. */
export async function leadForAgreement(agreementId) {
  return Lead.findOne({ agreement: agreementId });
}

// ---------------------------------------------------------------------------
// POST /deals/:leadId/attest   { statement: confirm|dispute, note? }
//
// Phase 3 (F15): each side's independent word on the close. Written once,
// before or after the admin decides. A dispute, or two statements that
// disagree, becomes a flag on the verification for the admin to see.
// ---------------------------------------------------------------------------
export const attestClose = async (req, res) => {
  try {
    const loaded = await loadForParty(req, res);
    if (!loaded) return;
    const { lead, role } = loaded;
    if (!lead.verification) {
      return res.status(409).json({ success: false, code: "NO_VERIFICATION", message: "The owner has not submitted this deal as closed yet" });
    }
    const { statement, note } = req.body || {};
    if (!["confirm", "dispute"].includes(statement)) {
      return res.status(400).json({ success: false, code: "INVALID_STATEMENT", message: "statement must be confirm or dispute" });
    }
    const verification = await TransactionVerification.findById(lead.verification);
    if (!verification) {
      return res.status(404).json({ success: false, code: "NOT_FOUND", message: "Verification not found" });
    }
    if (verification.attestations?.[role]?.statement) {
      return res.status(409).json({ success: false, code: "ALREADY_ATTESTED", message: "You have already given your statement" });
    }

    const now = new Date();
    verification.attestations[role] = {
      statement,
      note: typeof note === "string" ? note.trim().slice(0, 300) : "",
      at: now,
    };
    const other = verification.attestations[role === "owner" ? "buyer" : "owner"];
    const flags = new Set(verification.fraudFlags || []);
    if (statement === "dispute") flags.add("attestation_dispute");
    if (other?.statement && other.statement !== statement) flags.add("attestation_mismatch");
    if (statement === "confirm" && role === "buyer") flags.delete("attestation_missing");
    verification.fraudFlags = [...flags];
    await verification.save();

    res.status(200).json({ success: true, data: { statement, at: now } });
  } catch (error) {
    console.error("[deals] attest failed:", error);
    res.status(500).json({ success: false, message: "Could not record your statement" });
  }
};

/** Attach an agreement to the lead for (property, buyer), if one exists. */
export async function attachAgreementToLead({ propertyId, buyerId, agreementId, at = new Date() }) {
  const lead = await Lead.findOne({ property: propertyId, user: buyerId });
  if (!lead) return null;
  lead.agreement = agreementId;
  lead.agreementAt = at;
  await syncStage(lead, at);
  await lead.save();
  return lead;
}

/** Called when a verification is approved: the deal is closed. */
export async function closeLeadForVerification(verification, at = new Date()) {
  const lead = await Lead.findOne({ property: verification.property, user: verification.buyer });
  if (!lead) return null;
  lead.status = "converted";
  lead.verification = verification._id;
  lead.closedAt = at;
  await syncStage(lead, at);
  await lead.save();
  return lead;
}

/** Link a pending verification to its lead without closing it. */
export async function attachVerificationToLead(verification) {
  await Lead.updateOne(
    { property: verification.property, user: verification.buyer },
    { $set: { verification: verification._id } }
  );
}

export function formatIst(date) {
  try {
    return new Intl.DateTimeFormat("en-IN", {
      timeZone: "Asia/Kolkata",
      weekday: "short",
      day: "numeric",
      month: "short",
      hour: "numeric",
      minute: "2-digit",
    }).format(new Date(date));
  } catch {
    return new Date(date).toISOString();
  }
}

/**
 * Median first-response time, in hours, for one owner. `null` until three
 * leads have been answered: below that the number describes luck, not habit.
 */
export async function ownerResponseStats(ownerId) {
  const rows = await Lead.find({ propertyOwner: ownerId, firstOwnerResponseAt: { $ne: null } })
    .select("createdAt firstOwnerResponseAt")
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();
  if (rows.length < 3) return { responseHours: null, answered: rows.length };
  const hours = rows
    .map((r) => (new Date(r.firstOwnerResponseAt) - new Date(r.createdAt)) / 3600000)
    .filter((h) => Number.isFinite(h) && h >= 0)
    .sort((a, b) => a - b);
  if (hours.length < 3) return { responseHours: null, answered: hours.length };
  const mid = Math.floor(hours.length / 2);
  const median = hours.length % 2 ? hours[mid] : (hours[mid - 1] + hours[mid]) / 2;
  return { responseHours: Math.round(median * 10) / 10, answered: hours.length };
}

