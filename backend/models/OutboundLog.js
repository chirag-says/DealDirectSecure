import mongoose from "mongoose";

/**
 * One row per outbound message on a capped channel (WhatsApp, email).
 *
 * Exists only so the dispatcher can answer "how many did this person get this
 * week" with one indexed count. In-app and push are not logged: they are free
 * and uncapped. Rows expire after eight days; the cap window is seven.
 */
const outboundLogSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    channel: { type: String, enum: ["whatsapp", "email"], required: true },
    type: { type: String, required: true },
    at: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

outboundLogSchema.index({ user: 1, channel: 1, at: -1 });
outboundLogSchema.index({ at: 1 }, { expireAfterSeconds: 8 * 24 * 3600 });

const OutboundLog = mongoose.model("OutboundLog", outboundLogSchema);
export default OutboundLog;
