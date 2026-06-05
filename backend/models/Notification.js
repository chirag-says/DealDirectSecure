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

// Middleware to send email after a new notification is saved
notificationSchema.post("save", async function (doc) {
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
