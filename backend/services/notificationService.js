import Notification from "../models/Notification.js";
import OutboundLog from "../models/OutboundLog.js";
import SavedSearch from "../models/SavedSearch.js";
import User from "../models/userModel.js";
import { sendGeneralNotification } from "../utils/emailService.js";
import { candidateSearchFilter, searchMatchesProperty } from "../utils/savedSearchMatch.js";
import { sendPush } from "./pushService.js";
import { sendWhatsAppMessage } from "./whatsappService.js";

/**
 * Notification creation and delivery.
 *
 * Delivery used to live in Mongoose middleware: `post("save")` and
 * `post("insertMany")` on the Notification model sent the email as a side
 * effect of persistence. Three consequences, all removed here.
 *
 * "Who sends mail" was not greppable. Ten call sites across three controllers
 * wrote notifications, and every one of them mailed without saying so.
 *
 * The recipient lookup was N+1. `post("insertMany")` looped `User.findById`
 * once per document, and that is the fan-out path — saved-search matching
 * creates one notification per matching search, so a property matching 200
 * searches issued 200 sequential queries. `notifyUsers` does one `$in`.
 *
 * The model owned a network dependency. A schema file imported the mailer, so
 * persistence could not be reasoned about without reasoning about SMTP.
 *
 * PERSISTENCE IS THE SOURCE OF TRUTH. Every function here resolves once the
 * documents are written. Dispatch runs after that and its failures are logged,
 * never thrown: a notification that exists but was not emailed is a delivery
 * failure, not a persistence failure, and the in-app notification is still
 * there. Nothing in the request path awaits SMTP, push or WhatsApp.
 *
 * NO QUEUE, DELIBERATELY. Dispatch is fire-and-forget from the request path,
 * which is what it already was. A broker becomes the right answer when fan-out
 * grows past what one process should hold, or when delivery needs retries and
 * visibility; both are recorded as a follow-up rather than built here.
 *
 * ---------------------------------------------------------------------------
 * CHANNEL POLICY (Phase 0, engine E1)
 *
 * Every notification type resolves to one row of `NOTIFICATION_POLICY`, which
 * decides the channels beyond the in-app row that is always written:
 *
 *   push      every enabled device of the recipient (free, uncapped)
 *   email     "always"  as before: user preference only
 *             "capped"  also subject to the weekly cap below
 *             "never"
 *   whatsapp  only where true, and only when the user has a phone
 *   critical  exempt from the weekly cap (journey-critical events)
 *
 * Types that existed before the policy keep email "always" so nothing a user
 * received before is withheld now. The weekly cap applies to the two channels
 * that cost money or attention when overused; in-app and push are not counted.
 *
 * `kind` is the deep-link vocabulary shared with the clients. It is stamped
 * onto `data.kind` at write time so a notification can be routed without the
 * client reverse-engineering `type`.
 */

export const WEEKLY_CAP = 3;

const P = (kind, { push = true, email = "always", whatsapp = false, critical = false } = {}) =>
  Object.freeze({ kind, push, email, whatsapp, critical });

export const NOTIFICATION_POLICY = Object.freeze({
  // Pre-existing types. Email behaviour unchanged.
  general: P(null),
  interest: P("leads", { critical: true }), // WhatsApp is sent by markInterested itself
  "saved-search-match": P("property"),
  // A price cut on a home someone saved is the return trigger the research
  // rates highest, and the one event a buyer forgives a WhatsApp for.
  price_drop: P("property", { whatsapp: true, critical: true }),
  deal_verification: P("property", { critical: true }),
  deal_reward: P("dealReward", { whatsapp: true, critical: true }),

  // Deal room (Phase 2).
  deal_stage: P("deal", { email: "never" }),
  owner_replied: P("deal", { email: "never", whatsapp: true, critical: true }),
  message: P("message", { email: "never" }),
  visit_proposed: P("visit", { email: "capped", whatsapp: true, critical: true }),
  visit_confirmed: P("visit", { email: "capped", whatsapp: true, critical: true }),
  visit_cancelled: P("visit", { email: "never", whatsapp: true, critical: true }),
  visit_reminder: P("visit", { email: "never", whatsapp: true, critical: true }),
  visit_feedback_request: P("visit", { email: "never" }),
  agreement: P("deal", { whatsapp: true, critical: true }),
  owner_digest: P("digest"),

  // LTV (Phase 5).
  rental_renewal: P("property", { whatsapp: true, critical: true }),
  points_expiring: P("dealReward", { email: "capped" }),
  referral_invite: P("dealReward", { email: "never" }),

  // Trust (Phase 3).
  review_request: P("review", { email: "capped" }),
  review_published: P("review", { email: "capped" }),
  reward_hold: P("dealReward"),
  reward_milestone: P("dealReward", { email: "never" }),
});

const DEFAULT_POLICY = P(null);

export const policyFor = (type) => NOTIFICATION_POLICY[type] || DEFAULT_POLICY;

/**
 * Apply a per-recipient channel override to a policy row (Phase 1, F8).
 *
 * The override can only take channels AWAY. A saved search with
 * `notifyEmail: false` must not receive email even though the type's policy
 * says "always"; a saved search with `notifyEmail: true` must not thereby
 * gain WhatsApp, which its type never granted. Narrowing only is what makes
 * this safe to hand to any caller: the worst a wrong override can do is send
 * less.
 */
export function narrow(policy, override) {
  if (!override) return policy;
  return Object.freeze({
    ...policy,
    push: policy.push && override.push !== false,
    email: override.email === false ? "never" : policy.email,
    whatsapp: policy.whatsapp && override.whatsapp !== false,
  });
}

/** Ids the clients may route on. Everything else in `data` stays server-side. */
const ROUTABLE_KEYS = [
  "propertyId",
  "leadId",
  "visitId",
  "conversationId",
  "verificationId",
  "savedSearchId",
  "reviewId",
];

/** Shape an email from a notification document, preserving the old behaviour. */
function emailFor(doc, user) {
  let actionUrl = doc.data?.actionUrl || null;
  if (actionUrl) {
    actionUrl += actionUrl.includes("?")
      ? `&intendedFor=${encodeURIComponent(user.email)}`
      : `?intendedFor=${encodeURIComponent(user.email)}`;
  }
  return [user.email, user.name, doc.title, doc.message, actionUrl, doc.data?.actionText || null];
}

/** True when this user should receive email. Absent preference means yes. */
const wantsEmail = (user) => !!user?.email && user.preferences?.emailNotifications !== false;

/** True when this user can receive WhatsApp. Reuses the SMS preference as the opt-out. */
const wantsWhatsApp = (user) => !!user?.phone && user.preferences?.smsNotifications !== false;

function pushDataFor(doc, policy) {
  const out = { kind: doc.data?.kind || policy.kind || undefined, notificationId: String(doc._id) };
  for (const key of ROUTABLE_KEYS) {
    const value = doc.data?.[key];
    if (value !== undefined && value !== null) out[key] = String(value);
  }
  return out;
}

function whatsappTextFor(doc) {
  const raw = doc.data?.actionUrl;
  let link = null;
  if (raw) {
    link = /^https?:\/\//i.test(raw)
      ? raw
      : `${(process.env.CLIENT_URL || "https://dealdirect.in").replace(/\/+$/, "")}${raw}`;
  }
  return [doc.title, doc.message, link].filter(Boolean).join("\n");
}

/**
 * Weekly cap check for one user and channel. Counts the last seven days of
 * capped sends. Critical sends are logged too (they still count toward what a
 * person has received) but are never blocked by the count.
 */
async function underCap(userId, channel) {
  const since = new Date(Date.now() - 7 * 24 * 3600 * 1000);
  const n = await OutboundLog.countDocuments({ user: userId, channel, at: { $gte: since } });
  return n < WEEKLY_CAP;
}

function logOutbound(userId, channel, type) {
  return OutboundLog.create({ user: userId, channel, type }).catch((err) =>
    console.error("[notify] outbound log failed:", err.message)
  );
}

/**
 * Dispatch without blocking the caller.
 *
 * Errors are swallowed per recipient so one bad address cannot stop the rest,
 * and so a dead SMTP server cannot fail a request whose database write already
 * succeeded.
 */
function dispatch(pairs) {
  const pushes = [];

  for (const [doc, user, override] of pairs) {
    if (!user) continue;
    const policy = narrow(policyFor(doc.type), override);

    // Email, exactly as before for "always"; capped types check the budget first.
    if (policy.email !== "never" && wantsEmail(user)) {
      if (policy.email === "always" || policy.critical) {
        Promise.resolve()
          .then(() => sendGeneralNotification(...emailFor(doc, user)))
          .then(() => (policy.email === "capped" ? logOutbound(user._id, "email", doc.type) : null))
          .catch((err) => console.error(`[notify] delivery failed for ${doc._id}:`, err.message));
      } else {
        underCap(user._id, "email")
          .then((ok) => {
            if (!ok) return null;
            return sendGeneralNotification(...emailFor(doc, user)).then(() =>
              logOutbound(user._id, "email", doc.type)
            );
          })
          .catch((err) => console.error(`[notify] delivery failed for ${doc._id}:`, err.message));
      }
    }

    if (policy.whatsapp && wantsWhatsApp(user)) {
      (policy.critical ? Promise.resolve(true) : underCap(user._id, "whatsapp"))
        .then((ok) => {
          if (!ok) return null;
          return sendWhatsAppMessage(user.phone, whatsappTextFor(doc)).then((r) =>
            r?.success ? logOutbound(user._id, "whatsapp", doc.type) : null
          );
        })
        .catch((err) => console.error(`[notify] whatsapp failed for ${doc._id}:`, err.message));
    }

    if (policy.push) {
      pushes.push({
        userId: user._id,
        title: doc.title,
        body: doc.message,
        data: pushDataFor(doc, policy),
      });
    }
  }

  if (pushes.length) {
    Promise.resolve()
      .then(() => sendPush(pushes))
      .catch((err) => console.error("[notify] push failed:", err.message));
  }
}

const RECIPIENT_FIELDS = "name email phone preferences";

/**
 * A push with no in-app row. Used for chat messages, which already have their
 * own persistent surface (the thread) and would bury the Updates tab if every
 * one of them were also a notification. Throttled per (recipient, key) so a
 * burst of messages produces one banner.
 */
const pushThrottle = new Map();
const PUSH_THROTTLE_MS = 10 * 60 * 1000;

export async function pushOnly(userId, { title, body, data = {}, throttleKey = null }) {
  if (throttleKey) {
    const k = `${userId}:${throttleKey}`;
    const last = pushThrottle.get(k) || 0;
    if (Date.now() - last < PUSH_THROTTLE_MS) return { sent: 0, throttled: true };
    pushThrottle.set(k, Date.now());
    if (pushThrottle.size > 5000) pushThrottle.delete(pushThrottle.keys().next().value);
  }
  try {
    return await sendPush([{ userId, title, body, data }]);
  } catch (err) {
    console.error("[notify] pushOnly failed:", err.message);
    return { sent: 0 };
  }
}

/** Stamp the routing kind so clients never have to infer it from `type`. */
function withKind(payload) {
  const policy = policyFor(payload.type);
  if (!policy.kind || payload.data?.kind) return payload;
  return { ...payload, data: { ...(payload.data || {}), kind: policy.kind } };
}

/**
 * Create one notification and deliver it per policy.
 *
 * @param {ObjectId|string} userId
 * @param {{title: string, message: string, type?: string, data?: object}} payload
 * @returns {Promise<object>} the persisted notification
 */
export async function notifyUser(userId, payload) {
  const { channels, ...rest } = payload;
  const doc = await Notification.create({ user: userId, ...withKind(rest) });

  try {
    const user = await User.findById(userId).select(RECIPIENT_FIELDS).lean();
    if (user) dispatch([[doc, user, channels || null]]);
  } catch (err) {
    console.error("[notify] recipient lookup failed:", err.message);
  }

  return doc;
}

/**
 * Create many notifications and deliver them per policy.
 *
 * One `insertMany`, then ONE user query for the whole batch. Recipients repeat
 * across a batch rarely but legitimately, so the lookup is keyed on the unique
 * set of ids.
 *
 * @param {Array<{user: ObjectId|string, title: string, message: string, type?: string, data?: object}>} entries
 * @returns {Promise<object[]>} the persisted notifications
 */
export async function notifyUsers(entries) {
  if (!entries?.length) return [];

  // `channels` is a dispatch instruction, not part of the document. It is
  // lifted off here and paired back up by index after the insert, because
  // Mongoose would silently drop it and the override would vanish without a
  // word — the exact failure mode the saved-search flags had for a year.
  const overrides = entries.map((e) => e.channels || null);
  const docs = await Notification.insertMany(
    entries.map(({ channels, ...entry }) => withKind(entry))
  );

  try {
    const ids = [...new Set(docs.map((d) => String(d.user)))];
    const users = await User.find({ _id: { $in: ids } }).select(RECIPIENT_FIELDS).lean();
    const byId = new Map(users.map((u) => [String(u._id), u]));

    dispatch(
      docs
        .map((doc, i) => [doc, byId.get(String(doc.user)), overrides[i]])
        .filter(([, user]) => !!user)
    );
  } catch (err) {
    console.error("[notify] batch recipient lookup failed:", err.message);
  }

  return docs;
}

/**
 * Notify every active saved search a property matches.
 *
 * The matching rules are lifted unchanged from the two copies that lived in
 * propertyController, which had drifted: one filtered on city and price range,
 * the other on city alone. Both are here, and a caller that does not pass a
 * price simply skips the price test, which is what the second copy did.
 */
export async function notifySavedSearchMatches(property) {

  // The matching rules live in utils/savedSearchMatch.js so the price-drop
  // scan asks the same question the same way. See that file for why the city
  // comparison is anchored, case-insensitive and deliberately not trimmed.
  const searches = await SavedSearch.find(candidateSearchFilter(property)).lean();

  if (!searches.length) return [];

  const entries = [];
  const matchedIds = [];

  for (const search of searches) {
    if (!searchMatchesProperty(search, property)) continue;

    // The three flags NARROW delivery (Phase 1, F8). Before this they were
    // stored, shown in two clients, and read by nothing: a person who turned
    // email off kept receiving email. A search with every channel off is a
    // search that has been muted, and produces no row at all.
    const wantsInApp = search.notifyInApp !== false;
    const wantsEmail = search.notifyEmail !== false;
    const wantsPush = search.notifyPush !== false;
    if (!wantsInApp && !wantsEmail && !wantsPush) {
      matchedIds.push(search._id);
      continue;
    }

    entries.push({
      user: search.user,
      title: "New property matches your saved search",
      message: `${property.title || "A new property"} in ${property.address?.city || "your area"} matches "${search.name}"`,
      type: "saved-search-match",
      hidden: !wantsInApp,
      channels: { email: wantsEmail, push: wantsPush },
      data: { savedSearchId: search._id, propertyId: property._id },
    });
    matchedIds.push(search._id);
  }

  // Bookkeeping for the Searches list, including for muted searches: a person
  // who muted a search still wants to see that it is finding things.
  if (matchedIds.length) {
    SavedSearch.updateMany(
      { _id: { $in: matchedIds } },
      { $set: { lastMatchAt: new Date() }, $inc: { matchCount: 1 } }
    ).catch((err) => console.error("[notify] saved-search bookkeeping failed:", err.message));
  }

  return notifyUsers(entries);
}
