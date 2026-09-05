import crypto from "crypto";
import mongoose from "mongoose";
import Shortlist, { ShortlistShare } from "../models/Shortlist.js";
import Property from "../models/Property.js";
import User from "../models/userModel.js";

/**
 * The shortlist (Phase 1, F7).
 *
 * READ THE MODEL COMMENT FIRST. Nothing in this file may import `Lead` or
 * the notification service: a shortlist entry is private by definition, and
 * the absence of those imports is the enforcement, not a convention.
 *
 * There is no cap. That is the point of the feature: the five-enquiry cap
 * exists because an enquiry costs an owner their attention, and a private
 * save costs nobody anything. A generous cap is still applied to the bulk
 * merge below, because that one is a client handing us an array.
 */

const isId = (v) => mongoose.Types.ObjectId.isValid(v);

/** Everything a card needs, and nothing that identifies the owner. */
const CARD_FIELDS =
  "title price priceUnit listingType city locality address images categorizedImages status bhk area propertyTypeName isApproved isActive isBanned";

const MERGE_LIMIT = 200;
const SHARE_DAYS = 30;

/** A property is still worth showing if it exists; whether it is live is a flag. */
function cardFor(entry) {
  const p = entry.property;
  if (!p || typeof p !== "object") return null;

  // "sold" and "rented" are gone, not hidden, and the reader is told which.
  const UNAVAILABLE = ["pending", "inactive", "sold", "rented", "pending_verification"];
  const available =
    p.isApproved !== false && p.isBanned !== true && p.isActive !== false && !UNAVAILABLE.includes(p.status);

  return {
    id: entry._id,
    addedAt: entry.addedAt,
    note: entry.note || "",
    available,
    // "sold" and "rented" are gone-but-real outcomes; the client says so
    // rather than dropping the row, because a buyer wants to know that the
    // home they were considering went.
    unavailableReason: available ? null : p.status === "sold" || p.status === "rented" ? p.status : "unavailable",
    property: {
      _id: p._id,
      title: p.title,
      price: p.price,
      priceUnit: p.priceUnit,
      listingType: p.listingType,
      city: p.city || p.address?.city || null,
      locality: p.locality || p.address?.area || null,
      bhk: p.bhk,
      area: p.area,
      propertyTypeName: p.propertyTypeName,
      images: p.images || [],
      categorizedImages: p.categorizedImages,
      status: p.status,
    },
  };
}

// ---------------------------------------------------------------------------
// GET /shortlist
// ---------------------------------------------------------------------------
export const getMyShortlist = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));

    const [entries, total] = await Promise.all([
      Shortlist.find({ user: req.user._id })
        .populate("property", CARD_FIELDS)
        .sort({ addedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Shortlist.countDocuments({ user: req.user._id }),
    ]);

    // A property deleted outright leaves a populate of null. The row is
    // useless to the reader, so it is dropped from the response and from the
    // collection: the buyer never asked to keep a pointer to nothing.
    const orphans = entries.filter((e) => !e.property).map((e) => e._id);
    if (orphans.length) {
      Shortlist.deleteMany({ _id: { $in: orphans } }).catch((err) =>
        console.error("[shortlist] orphan cleanup failed:", err.message)
      );
    }

    const data = entries.map(cardFor).filter(Boolean);

    res.status(200).json({
      success: true,
      data,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    console.error("[shortlist] list failed:", error);
    res.status(500).json({ success: false, message: "Could not load your shortlist" });
  }
};

// ---------------------------------------------------------------------------
// POST /shortlist   { propertyId, note? }
// ---------------------------------------------------------------------------
export const addToShortlist = async (req, res) => {
  try {
    const { propertyId, note } = req.body || {};
    if (!isId(propertyId)) {
      return res.status(400).json({ success: false, code: "INVALID_ID", message: "A valid propertyId is required" });
    }

    const property = await Property.findById(propertyId).select("_id status isApproved isActive isBanned").lean();
    if (!property) {
      return res.status(404).json({ success: false, code: "NOT_FOUND", message: "Property not found" });
    }

    const clean = typeof note === "string" ? note.trim().slice(0, 300) : "";

    // Idempotent: saving twice is one row, and the second save may carry a
    // note. `addedAt` is not touched, so the list keeps its true order.
    const entry = await Shortlist.findOneAndUpdate(
      { user: req.user._id, property: propertyId },
      { $setOnInsert: { addedAt: new Date() }, ...(clean ? { $set: { note: clean } } : {}) },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    ).lean();

    const total = await Shortlist.countDocuments({ user: req.user._id });
    res.status(200).json({ success: true, data: { id: entry._id, addedAt: entry.addedAt }, total });
  } catch (error) {
    // Two devices saving the same property at the same instant race the
    // upsert. The outcome they both wanted is already true.
    if (error?.code === 11000) {
      return res.status(200).json({ success: true, duplicate: true });
    }
    console.error("[shortlist] add failed:", error);
    res.status(500).json({ success: false, message: "Could not save this property" });
  }
};

// ---------------------------------------------------------------------------
// POST /shortlist/merge   { propertyIds: [] }
//
// The mobile app kept its shortlist on the device before this collection
// existed. On the first authenticated launch it hands the local list over.
// Unknown and duplicate ids are skipped rather than failing the batch: a
// migration that refuses because one listing was deleted is a migration that
// never completes.
// ---------------------------------------------------------------------------
export const mergeShortlist = async (req, res) => {
  try {
    const raw = Array.isArray(req.body?.propertyIds) ? req.body.propertyIds : [];
    const ids = [...new Set(raw.filter(isId).map(String))].slice(0, MERGE_LIMIT);
    if (!ids.length) {
      return res.status(200).json({ success: true, added: 0, skipped: raw.length });
    }

    const known = await Property.find({ _id: { $in: ids } }).select("_id").lean();
    const knownIds = known.map((p) => String(p._id));

    if (knownIds.length) {
      await Shortlist.bulkWrite(
        knownIds.map((id) => ({
          updateOne: {
            filter: { user: req.user._id, property: id },
            update: { $setOnInsert: { addedAt: new Date() } },
            upsert: true,
          },
        })),
        { ordered: false }
      );
    }

    const total = await Shortlist.countDocuments({ user: req.user._id });
    res.status(200).json({ success: true, added: knownIds.length, skipped: raw.length - knownIds.length, total });
  } catch (error) {
    console.error("[shortlist] merge failed:", error);
    res.status(500).json({ success: false, message: "Could not merge your saved properties" });
  }
};

// ---------------------------------------------------------------------------
// DELETE /shortlist/:propertyId
// ---------------------------------------------------------------------------
export const removeFromShortlist = async (req, res) => {
  try {
    const { propertyId } = req.params;
    if (!isId(propertyId)) {
      return res.status(400).json({ success: false, code: "INVALID_ID", message: "Invalid property id" });
    }
    const result = await Shortlist.deleteOne({ user: req.user._id, property: propertyId });
    const total = await Shortlist.countDocuments({ user: req.user._id });
    // Removing something already gone is the state the caller wanted.
    res.status(200).json({ success: true, removed: result.deletedCount === 1, total });
  } catch (error) {
    console.error("[shortlist] remove failed:", error);
    res.status(500).json({ success: false, message: "Could not remove this property" });
  }
};

// ---------------------------------------------------------------------------
// PATCH /shortlist/:propertyId   { note }
// ---------------------------------------------------------------------------
export const updateShortlistNote = async (req, res) => {
  try {
    const { propertyId } = req.params;
    if (!isId(propertyId)) {
      return res.status(400).json({ success: false, code: "INVALID_ID", message: "Invalid property id" });
    }
    const note = typeof req.body?.note === "string" ? req.body.note.trim().slice(0, 300) : "";
    const entry = await Shortlist.findOneAndUpdate(
      { user: req.user._id, property: propertyId },
      { $set: { note } },
      { new: true }
    ).lean();
    if (!entry) {
      return res.status(404).json({ success: false, code: "NOT_SHORTLISTED", message: "This property is not on your shortlist" });
    }
    res.status(200).json({ success: true, data: { note: entry.note } });
  } catch (error) {
    console.error("[shortlist] note failed:", error);
    res.status(500).json({ success: false, message: "Could not save your note" });
  }
};

// ---------------------------------------------------------------------------
// GET /shortlist/ids   — the client's cheap sync of "what is already saved"
// ---------------------------------------------------------------------------
export const getShortlistIds = async (req, res) => {
  try {
    const rows = await Shortlist.find({ user: req.user._id }).select("property").lean();
    res.status(200).json({ success: true, data: rows.map((r) => String(r.property)) });
  } catch (error) {
    console.error("[shortlist] ids failed:", error);
    res.status(500).json({ success: false, message: "Could not load your shortlist" });
  }
};

// ---------------------------------------------------------------------------
// POST /shortlist/share
// ---------------------------------------------------------------------------
export const createShortlistShare = async (req, res) => {
  try {
    const count = await Shortlist.countDocuments({ user: req.user._id });
    if (count === 0) {
      return res.status(409).json({ success: false, code: "EMPTY_SHORTLIST", message: "Save a home before sharing your list" });
    }

    // One live link per person. Sharing again rotates the token, which is
    // also how a person revokes a link they regret: the old one stops working.
    await ShortlistShare.updateMany(
      { user: req.user._id, revokedAt: null },
      { $set: { revokedAt: new Date() } }
    );

    const firstName = String(req.user.name || "").trim().split(/\s+/)[0] || "A buyer";
    const share = await ShortlistShare.create({
      user: req.user._id,
      token: crypto.randomBytes(24).toString("base64url"),
      label: firstName.slice(0, 60),
      expiresAt: new Date(Date.now() + SHARE_DAYS * 86400 * 1000),
    });

    res.status(201).json({
      success: true,
      data: { token: share.token, expiresAt: share.expiresAt, count },
    });
  } catch (error) {
    console.error("[shortlist] share failed:", error);
    res.status(500).json({ success: false, message: "Could not create a share link" });
  }
};

// ---------------------------------------------------------------------------
// DELETE /shortlist/share
// ---------------------------------------------------------------------------
export const revokeShortlistShare = async (req, res) => {
  try {
    const result = await ShortlistShare.updateMany(
      { user: req.user._id, revokedAt: null },
      { $set: { revokedAt: new Date() } }
    );
    res.status(200).json({ success: true, revoked: result.modifiedCount });
  } catch (error) {
    console.error("[shortlist] revoke failed:", error);
    res.status(500).json({ success: false, message: "Could not revoke the link" });
  }
};

// ---------------------------------------------------------------------------
// GET /shortlist/shared/:token   — PUBLIC, read-only
//
// The token is the whole authorisation. What it grants is deliberately
// narrow: the list, the label, and nothing about the person who made it.
// ---------------------------------------------------------------------------
export const getSharedShortlist = async (req, res) => {
  try {
    const { token } = req.params;
    if (typeof token !== "string" || token.length < 20 || token.length > 100) {
      return res.status(404).json({ success: false, code: "LINK_NOT_FOUND", message: "This link is not valid" });
    }

    const share = await ShortlistShare.findOne({ token }).lean();
    const expired = share && new Date(share.expiresAt) <= new Date();
    // One answer for missing, revoked and expired: a holder of a dead link
    // learns nothing about which of the three it was.
    if (!share || share.revokedAt || expired) {
      return res.status(404).json({ success: false, code: "LINK_NOT_FOUND", message: "This link has expired or was withdrawn" });
    }

    const entries = await Shortlist.find({ user: share.user })
      .populate("property", CARD_FIELDS)
      .sort({ addedAt: -1 })
      .limit(100)
      .lean();

    ShortlistShare.updateOne(
      { _id: share._id },
      { $inc: { views: 1 }, $set: { lastViewedAt: new Date() } }
    ).catch(() => {});

    res.status(200).json({
      success: true,
      data: {
        label: share.label,
        // The notes are the author's private thinking, not part of the share.
        properties: entries.map(cardFor).filter(Boolean).map(({ note, ...rest }) => rest),
        expiresAt: share.expiresAt,
      },
    });
  } catch (error) {
    console.error("[shortlist] shared read failed:", error);
    res.status(500).json({ success: false, message: "Could not load this list" });
  }
};

export { User };
