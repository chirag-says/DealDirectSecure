import { Event, EventRollup } from "../models/Event.js";

const IST_OFFSET_MS = 5.5 * 3600 * 1000;

/** YYYY-MM-DD of an instant, in IST. */
export function istDay(date) {
  return new Date(date.getTime() + IST_OFFSET_MS).toISOString().slice(0, 10);
}

/** [start, end) UTC bounds of an IST calendar day. */
export function istDayBounds(day) {
  const start = new Date(`${day}T00:00:00.000Z`).getTime() - IST_OFFSET_MS;
  return { start: new Date(start), end: new Date(start + 86400 * 1000) };
}

/**
 * Fold raw events into one row per (day, name).
 *
 * Runs nightly for yesterday, and re-runs any day since the cursor that has
 * not been rolled up, so a night the process was down is caught up the next
 * night. The upsert makes re-running a day harmless: counts are recomputed
 * from the raw rows, never incremented.
 */
export async function rollupEvents({ now = new Date(), cursor = null } = {}) {
  const yesterday = istDay(new Date(now.getTime() - 86400 * 1000));
  const firstDay = cursor?.day ? nextDay(cursor.day) : yesterday;

  let day = firstDay <= yesterday ? firstDay : yesterday;
  let days = 0;
  let rows = 0;

  while (day <= yesterday) {
    const { start, end } = istDayBounds(day);
    const groups = await Event.aggregate([
      { $match: { at: { $gte: start, $lt: end } } },
      {
        $group: {
          _id: "$name",
          count: { $sum: 1 },
          users: { $addToSet: { $ifNull: ["$user", "$anon"] } },
        },
      },
    ]);

    for (const g of groups) {
      await EventRollup.updateOne(
        { day, name: g._id },
        { $set: { count: g.count, users: g.users.filter(Boolean).length } },
        { upsert: true }
      );
      rows += 1;
    }

    days += 1;
    day = nextDay(day);
  }

  return { cursor: { day: yesterday }, days, rows };
}

function nextDay(day) {
  const d = new Date(`${day}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}
