import PushToken from "../models/PushToken.js";

/**
 * Device registration for push (Phase 0, F6).
 *
 * POST   /users/push-token   { token, platform, installationId?, appVersion? }
 * DELETE /users/push-token   { token }
 *
 * A token is re-pointed at whoever registers it last: the same phone signing
 * into a second account must not keep receiving the first account's pushes.
 * Registering a token that was disabled re-enables it, because the client is
 * the authority on whether the token is current.
 */

const PLATFORMS = new Set(["ios", "android"]);

export const registerPushToken = async (req, res) => {
  try {
    const { token, platform, installationId, appVersion } = req.body || {};

    if (!PushToken.isValidToken(token)) {
      return res.status(400).json({ success: false, code: "INVALID_PUSH_TOKEN", message: "A valid Expo push token is required" });
    }
    if (!PLATFORMS.has(platform)) {
      return res.status(400).json({ success: false, code: "INVALID_PLATFORM", message: "platform must be ios or android" });
    }

    const doc = await PushToken.findOneAndUpdate(
      { token },
      {
        $set: {
          user: req.user._id,
          platform,
          installationId: typeof installationId === "string" ? installationId.slice(0, 128) : null,
          appVersion: typeof appVersion === "string" ? appVersion.slice(0, 32) : null,
          lastSeenAt: new Date(),
          disabledAt: null,
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    ).lean();

    res.status(200).json({ success: true, data: { id: doc._id, platform: doc.platform } });
  } catch (error) {
    console.error("[push] register failed:", error);
    res.status(500).json({ success: false, message: "Could not register this device" });
  }
};

export const removePushToken = async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!PushToken.isValidToken(token)) {
      return res.status(400).json({ success: false, code: "INVALID_PUSH_TOKEN", message: "A valid Expo push token is required" });
    }

    // Only the account the token currently belongs to may remove it.
    const result = await PushToken.deleteOne({ token, user: req.user._id });
    res.status(200).json({ success: true, removed: result.deletedCount === 1 });
  } catch (error) {
    console.error("[push] remove failed:", error);
    res.status(500).json({ success: false, message: "Could not remove this device" });
  }
};

/** Used by logout-all: every device of the account stops receiving pushes. */
export const removeAllPushTokensFor = (userId) => PushToken.deleteMany({ user: userId });
