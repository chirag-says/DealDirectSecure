import mongoose from "mongoose";

/**
 * A device that can be reached with a push notification.
 *
 * One document per device token. A token identifies an installation, not a
 * person: when a second account signs in on the same phone the token is
 * re-pointed at that account (see `registerPushToken`), so a device never
 * receives another account's notifications.
 *
 * `disabledAt` is set when Expo reports `DeviceNotRegistered` for the token
 * (app uninstalled, token rotated). Disabled tokens are skipped by the sender
 * and pruned by the `push-token-prune` job; they are kept briefly so a client
 * that re-registers the same string simply re-enables it.
 */
const pushTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    token: { type: String, required: true, unique: true },
    platform: { type: String, enum: ["ios", "android"], required: true },
    installationId: { type: String, default: null },
    appVersion: { type: String, default: null },
    lastSeenAt: { type: Date, default: Date.now },
    disabledAt: { type: Date, default: null },
  },
  { timestamps: true }
);

/** Expo push tokens are the only shape the sender knows how to address. */
export const EXPO_PUSH_TOKEN_RE = /^Expo(?:nent)?PushToken\[[A-Za-z0-9_-]{8,}\]$/;

pushTokenSchema.statics.isValidToken = (value) =>
  typeof value === "string" && EXPO_PUSH_TOKEN_RE.test(value);

const PushToken = mongoose.model("PushToken", pushTokenSchema);
export default PushToken;
