import PushToken from "../models/PushToken.js";

/**
 * Push delivery through the Expo Push Service.
 *
 * One HTTP endpoint, batches of up to 100 messages, a ticket per message. The
 * only ticket error acted on is `DeviceNotRegistered`: the token is disabled
 * on the spot so the next dispatch does not pay for it. Receipts are polled
 * later by the `push-receipts` job for the same error, because a token can be
 * accepted at send time and rejected by FCM/APNs afterwards.
 *
 * The endpoint is configurable so the integration harness, which blocks all
 * outbound network, can point it at a loopback fake. Nothing here throws to a
 * caller: a failed send is logged and the in-app notification stands.
 */

const DEFAULT_URL = "https://exp.host/--/api/v2/push/send";
const RECEIPTS_URL = "https://exp.host/--/api/v2/push/getReceipts";
const BATCH = 100;

const pushUrl = () => process.env.EXPO_PUSH_URL || DEFAULT_URL;
const receiptsUrl = () =>
  process.env.EXPO_PUSH_RECEIPTS_URL ||
  (process.env.EXPO_PUSH_URL ? process.env.EXPO_PUSH_URL.replace(/\/send$/, "/getReceipts") : RECEIPTS_URL);

/** Ticket ids awaiting a receipt, keyed to the token they were sent to. Bounded. */
const pendingTickets = new Map();
const MAX_PENDING = 5000;

function rememberTicket(id, token) {
  if (!id) return;
  if (pendingTickets.size >= MAX_PENDING) {
    const oldest = pendingTickets.keys().next().value;
    pendingTickets.delete(oldest);
  }
  pendingTickets.set(id, token);
}

async function disableTokens(tokens) {
  if (!tokens.length) return;
  await PushToken.updateMany(
    { token: { $in: tokens }, disabledAt: null },
    { $set: { disabledAt: new Date() } }
  );
}

function headers() {
  const h = { "Content-Type": "application/json", Accept: "application/json" };
  if (process.env.EXPO_ACCESS_TOKEN) h.Authorization = `Bearer ${process.env.EXPO_ACCESS_TOKEN}`;
  return h;
}

/**
 * Send one notification to every enabled device of each user.
 *
 * @param {Array<{userId: string, title: string, body: string, data?: object}>} messages
 * @returns {Promise<{sent: number, disabled: number}>}
 */
export async function sendPush(messages) {
  if (!messages?.length) return { sent: 0, disabled: 0 };

  const userIds = [...new Set(messages.map((m) => String(m.userId)))];
  const tokens = await PushToken.find({ user: { $in: userIds }, disabledAt: null })
    .select("user token")
    .lean();
  if (!tokens.length) return { sent: 0, disabled: 0 };

  const byUser = new Map();
  for (const t of tokens) {
    const key = String(t.user);
    if (!byUser.has(key)) byUser.set(key, []);
    byUser.get(key).push(t.token);
  }

  const payloads = [];
  for (const m of messages) {
    for (const token of byUser.get(String(m.userId)) || []) {
      payloads.push({
        to: token,
        title: m.title,
        body: m.body,
        data: m.data || {},
        sound: "default",
        channelId: "default",
        priority: "high",
      });
    }
  }

  let sent = 0;
  const dead = [];

  for (let i = 0; i < payloads.length; i += BATCH) {
    const chunk = payloads.slice(i, i + BATCH);
    try {
      const res = await fetch(pushUrl(), {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(chunk),
      });
      const json = await res.json().catch(() => ({}));
      const tickets = Array.isArray(json?.data) ? json.data : [];

      tickets.forEach((ticket, idx) => {
        const token = chunk[idx]?.to;
        if (ticket?.status === "ok") {
          sent += 1;
          rememberTicket(ticket.id, token);
        } else if (ticket?.details?.error === "DeviceNotRegistered") {
          dead.push(token);
        } else {
          console.warn("[push] ticket error:", ticket?.message || ticket?.details?.error || "unknown");
        }
      });
    } catch (err) {
      console.error("[push] send failed:", err.message);
    }
  }

  await disableTokens(dead).catch((err) => console.error("[push] disable failed:", err.message));
  return { sent, disabled: dead.length };
}

/**
 * Poll receipts for tickets sent earlier and disable tokens FCM/APNs rejected.
 * Called by the `push-receipts` job; safe to call with nothing pending.
 */
export async function collectReceipts() {
  if (pendingTickets.size === 0) return { checked: 0, disabled: 0 };

  const ids = [...pendingTickets.keys()].slice(0, 1000);
  const dead = [];
  let checked = 0;

  try {
    const res = await fetch(receiptsUrl(), {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ ids }),
    });
    const json = await res.json().catch(() => ({}));
    const receipts = json?.data || {};

    for (const id of ids) {
      const receipt = receipts[id];
      if (!receipt) continue; // not ready yet; ask again next run
      checked += 1;
      const token = pendingTickets.get(id);
      pendingTickets.delete(id);
      if (receipt.status === "error" && receipt.details?.error === "DeviceNotRegistered") {
        dead.push(token);
      }
    }
  } catch (err) {
    console.error("[push] receipts failed:", err.message);
  }

  await disableTokens(dead).catch((err) => console.error("[push] disable failed:", err.message));
  return { checked, disabled: dead.length };
}

/** Test seam. */
export const _pending = pendingTickets;
