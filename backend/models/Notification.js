import mongoose from "mongoose";

const notificationSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, default: "general" }, // e.g., saved-search, lead, agreement
    data: { type: Object, default: {} },
    isRead: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// ============================================
// NO DELIVERY HERE (Phase 3E).
//
// This model used to send email from post("save") and post("insertMany"),
// looking the recipient up itself. Persistence and network delivery are
// different concerns, and coupling them had three costs: "who sends mail" was
// not greppable across ten call sites, post("insertMany") looped
// User.findById once per document (the fan-out N+1), and a schema file
// imported the mailer.
//
// Delivery now lives in services/notificationService.js. Writing a Notification
// document directly persists it and sends nothing — deliberate, and asserted by
// the integration suite, which also fails if a controller reintroduces a direct
// Notification.create.
//
// The rule the old hook enforced is preserved there: only a newly created
// notification mails. Marking one read is a save, and the hook used to send
// again on every one, so opening the notification centre re-mailed each item.
// ============================================

const Notification = mongoose.model("Notification", notificationSchema);
export default Notification;
