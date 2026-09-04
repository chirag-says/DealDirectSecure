import PushToken from "../models/PushToken.js";

const KEEP_DISABLED_DAYS = 30;
const KEEP_UNSEEN_DAYS = 180;

/**
 * Remove tokens that cannot be used again.
 *
 * Disabled tokens are kept for a month so a client re-registering the same
 * string re-enables it without a new row; after that they are noise. Tokens
 * not seen for six months belong to installs that never opened the app again
 * and would only produce `DeviceNotRegistered` tickets.
 */
export async function pruneDisabledTokens({ now = new Date() } = {}) {
  const disabledBefore = new Date(now.getTime() - KEEP_DISABLED_DAYS * 86400 * 1000);
  const unseenBefore = new Date(now.getTime() - KEEP_UNSEEN_DAYS * 86400 * 1000);

  const disabled = await PushToken.deleteMany({ disabledAt: { $ne: null, $lte: disabledBefore } });
  const unseen = await PushToken.deleteMany({ disabledAt: null, lastSeenAt: { $lte: unseenBefore } });

  return { removedDisabled: disabled.deletedCount, removedUnseen: unseen.deletedCount };
}
