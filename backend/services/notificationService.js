import Notification from "../models/Notification.js";
import SavedSearch from "../models/SavedSearch.js";
import User from "../models/userModel.js";
import { sendGeneralNotification } from "../utils/emailService.js";
import { escapeRegExp } from "../utils/escapeRegExp.js";

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
 * there. Nothing in the request path awaits SMTP.
 *
 * NO QUEUE, DELIBERATELY. Dispatch is fire-and-forget from the request path,
 * which is what it already was. A broker becomes the right answer when fan-out
 * grows past what one process should hold, or when delivery needs retries and
 * visibility; both are recorded as a follow-up rather than built here.
 */

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

/**
 * Dispatch without blocking the caller.
 *
 * Errors are swallowed per recipient so one bad address cannot stop the rest,
 * and so a dead SMTP server cannot fail a request whose database write already
 * succeeded.
 */
function dispatch(pairs) {
  for (const [doc, user] of pairs) {
    Promise.resolve()
      .then(() => sendGeneralNotification(...emailFor(doc, user)))
      .catch((err) => console.error(`[notify] delivery failed for ${doc._id}:`, err.message));
  }
}

/**
 * Create one notification and email its recipient.
 *
 * @param {ObjectId|string} userId
 * @param {{title: string, message: string, type?: string, data?: object}} payload
 * @returns {Promise<object>} the persisted notification
 */
export async function notifyUser(userId, payload) {
  const doc = await Notification.create({ user: userId, ...payload });

  try {
    const user = await User.findById(userId).select("name email preferences").lean();
    if (wantsEmail(user)) dispatch([[doc, user]]);
  } catch (err) {
    console.error("[notify] recipient lookup failed:", err.message);
  }

  return doc;
}

/**
 * Create many notifications and email their recipients.
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

  const docs = await Notification.insertMany(entries);

  try {
    const ids = [...new Set(docs.map((d) => String(d.user)))];
    const users = await User.find({ _id: { $in: ids } })
      .select("name email preferences").lean();
    const byId = new Map(users.map((u) => [String(u._id), u]));

    dispatch(
      docs
        .map((doc) => [doc, byId.get(String(doc.user))])
        .filter(([, user]) => wantsEmail(user))
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
  const city = property.address?.city || "";

  // The city test runs in MongoDB (Phase 4.2). It used to be a JavaScript
  // comparison over every active saved search, so a property in one city pulled
  // every watcher of every other city across the wire before discarding them.
  //
  // CASE SEMANTICS ARE PRESERVED EXACTLY, including one that looks like a bug.
  // The old comparison was `lower(propertyCity) === lower(savedCity)`:
  // case-insensitive, anchored, and NOT trimmed — so " Pune" did not match
  // "Pune". The anchored `^...$` regex with `i` reproduces all three. Making it
  // trim would silently widen who gets notified, which is a product change
  // rather than a performance one.
  //
  // The city is escaped because it reaches a regex. Without that, a saved
  // search for "P.ne" would match "Pune".
  //
  // A search with no city — "" is the schema default — still matches every
  // city, as it always did. `$exists: false` and `null` cover documents written
  // before the default existed or inserted straight through the driver.
  const searches = await SavedSearch.find({
    isActive: true,
    $or: [
      { "filters.city": { $in: ["", null] } },
      { "filters.city": { $exists: false } },
      { "filters.city": { $regex: `^${escapeRegExp(city)}$`, $options: "i" } },
    ],
  }).lean();

  if (!searches.length) return [];

  const price = property.price;
  const entries = [];

  for (const search of searches) {
    const f = search.filters || {};

    // The price bucket stays in JavaScript, deliberately. It compares against
    // three hard-coded thresholds rather than a stored bound, so there is no
    // indexable predicate to push down — expressing it as $lt/$gte clauses
    // would be more code saying the same thing, further from the buckets it
    // encodes, for no measured gain.
    if (f.priceRange && typeof price === "number") {
      const matchPrice =
        f.priceRange === "low" ? price < 5000000
          : f.priceRange === "mid" ? price >= 5000000 && price <= 15000000
            : f.priceRange === "high" ? price > 15000000
              : false;
      if (!matchPrice) continue;
    }

    entries.push({
      user: search.user,
      title: "New property matches your saved search",
      message: `${property.title || "A new property"} in ${property.address?.city || "your area"} matches "${search.name}"`,
      type: "saved-search-match",
      data: { savedSearchId: search._id, propertyId: property._id },
    });
  }

  return notifyUsers(entries);
}
