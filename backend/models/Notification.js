import mongoose from "mongoose";
import User from "./userModel.js";
import { sendGeneralNotification } from "../utils/emailService.js";

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
// Remember whether this save was an insert.
//
// By the time post("save") runs, doc.isNew is already false, so the hook below
// cannot tell an insert from an update on its own. $locals is Mongoose's
// documented per-document scratch space and is not persisted.
// ============================================
notificationSchema.pre("save", function (next) {
  this.$locals.wasNew = this.isNew;
  next();
});

// Middleware to send email after a new notification is saved
notificationSchema.post("save", async function (doc) {
  // ============================================
  // Only a newly created notification sends email.
  //
  // This hook fires on EVERY save, and marking a notification read is a save:
  // notificationController.markNotificationRead does
  //   notification.isRead = true; await notification.save();
  // so opening the notification centre re-sent the email for each item read,
  // and claiming a reward re-sent the "Claim Your Reward" notice after it had
  // been claimed. One notification plus K read-toggles produced K+1 emails.
  //
  // markAllNotificationsRead uses updateMany, which bypasses document
  // middleware entirely — so the same user action emailed or did not depending
  // on which button was pressed. This makes both paths behave the same way.
  //
  // Scope note: email dispatch stays in the model for now. Moving it into an
  // explicit service is the right fix for the N+1 lookup and the per-message
  // SMTP handshake, and is deliberately left to a separate change.
  // ============================================
  if (!doc.$locals?.wasNew) return;

  try {
    const user = await User.findById(doc.user);
    if (user && user.email && user.preferences?.emailNotifications !== false) {
      // Send asynchronously without blocking
      let actionUrl = doc.data?.actionUrl || null;
      if (actionUrl) {
        actionUrl += actionUrl.includes("?") 
          ? `&intendedFor=${encodeURIComponent(user.email)}` 
          : `?intendedFor=${encodeURIComponent(user.email)}`;
      }
      const actionText = doc.data?.actionText || null;
      sendGeneralNotification(user.email, user.name, doc.title, doc.message, actionUrl, actionText).catch((err) =>
        console.error("Failed to send email notification on save:", err)
      );
    }
  } catch (err) {
    console.error("Error in notification post-save hook:", err);
  }
});

// Middleware to send email after multiple notifications are inserted
notificationSchema.post("insertMany", async function (docs) {
  try {
    for (const doc of docs) {
      const user = await User.findById(doc.user);
      if (user && user.email && user.preferences?.emailNotifications !== false) {
        // Send asynchronously without blocking
        let actionUrl = doc.data?.actionUrl || null;
        if (actionUrl) {
          actionUrl += actionUrl.includes("?") 
            ? `&intendedFor=${encodeURIComponent(user.email)}` 
            : `?intendedFor=${encodeURIComponent(user.email)}`;
        }
        const actionText = doc.data?.actionText || null;
        sendGeneralNotification(user.email, user.name, doc.title, doc.message, actionUrl, actionText).catch((err) =>
          console.error("Failed to send email notification on insertMany:", err)
        );
      }
    }
  } catch (err) {
    console.error("Error in notification post-insertMany hook:", err);
  }
});

const Notification = mongoose.model("Notification", notificationSchema);
export default Notification;
