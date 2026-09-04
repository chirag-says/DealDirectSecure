import mongoose from "mongoose";

/**
 * Product usage events (F3).
 *
 * Raw rows live 90 days, then the TTL index removes them; the `events-rollup`
 * job folds each day into `EventRollup` so the funnel numbers survive the raw
 * data. Nothing here is personal beyond the user id: `props` is whitelisted
 * per event name in `controllers/eventController.js`, and free text is
 * refused at the boundary.
 */
const eventSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    /** A per-installation id for signed-out sessions. Never a device fingerprint. */
    anon: { type: String, default: null },
    name: { type: String, required: true },
    props: { type: mongoose.Schema.Types.Mixed, default: {} },
    platform: { type: String, enum: ["web", "android", "ios", "unknown"], default: "unknown" },
    at: { type: Date, required: true },
  },
  { versionKey: false }
);

eventSchema.index({ name: 1, at: -1 });
eventSchema.index({ user: 1, at: -1 });
eventSchema.index({ at: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });

export const Event = mongoose.model("Event", eventSchema);

const eventRollupSchema = new mongoose.Schema(
  {
    day: { type: String, required: true }, // YYYY-MM-DD, IST
    name: { type: String, required: true },
    count: { type: Number, default: 0 },
    users: { type: Number, default: 0 },
  },
  { versionKey: false }
);

eventRollupSchema.index({ day: 1, name: 1 }, { unique: true });

export const EventRollup = mongoose.model("EventRollup", eventRollupSchema);
