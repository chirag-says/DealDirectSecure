/**
 * Helpers for the {label, value, month}[] series the dashboard API returns.
 *
 * Separate from `Sparkline.jsx` so that file only exports components, which is
 * what React Fast Refresh needs to hot-swap one without remounting the tree.
 *
 * Two things about the shape of this data drive everything below, both of
 * them coming from the `$group` by `%Y-%m` in adminController.getDashboardStats:
 *
 *   1. The final bucket is the CURRENT month, still accumulating. Nineteen
 *      days measured against a full thirty-one is not a comparison, and
 *      reporting it as one prints a decline every month until the last week
 *      of it.
 *
 *   2. Months with no records produce no bucket at all — the aggregation does
 *      not zero-fill. So "the last two points" are not necessarily two
 *      consecutive months, and a delta across a gap needs saying so.
 */

/** "YYYY-MM" for the current month, matching the API's bucket keys. */
function currentMonthKey(now = new Date()) {
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
}

/** Months since year zero, for testing whether two buckets are adjacent. */
function monthOrdinal(key) {
  const [year, month] = String(key).split("-").map(Number);
  return Number.isFinite(year) && Number.isFinite(month)
    ? year * 12 + (month - 1)
    : null;
}

/** Pulls the numeric values out of a series, tolerating raw numbers too. */
export function seriesValues(data) {
  return (data ?? [])
    .map((d) => Number(typeof d === "object" ? d?.value : d))
    .filter((n) => Number.isFinite(n));
}

/**
 * True when the last point of the series is the month we are currently in,
 * and therefore incomplete. Series that carry no `month` field are assumed
 * complete rather than guessed at.
 */
export function hasPartialTail(data, now = new Date()) {
  const last = (data ?? [])[data?.length - 1];
  return Boolean(last?.month) && last.month === currentMonthKey(now);
}

/**
 * Change between the two most recent COMPLETE periods.
 *
 * Returns null when there is no such pair, so callers render nothing rather
 * than a fabricated "0%". Never compares against the in-progress month.
 */
export function seriesDelta(data, now = new Date()) {
  const points = (data ?? []).filter((p) =>
    Number.isFinite(Number(typeof p === "object" ? p?.value : p))
  );
  if (points.length < 2) return null;

  const thisMonth = currentMonthKey(now);
  const complete = points.filter(
    (p) => typeof p !== "object" || !p?.month || p.month !== thisMonth
  );
  if (complete.length < 2) return null;

  const to = complete[complete.length - 1];
  const from = complete[complete.length - 2];

  const toValue = Number(typeof to === "object" ? to.value : to);
  const fromValue = Number(typeof from === "object" ? from.value : from);
  const change = toValue - fromValue;

  const toOrdinal = monthOrdinal(to?.month);
  const fromOrdinal = monthOrdinal(from?.month);

  return {
    change,
    trend: change > 0 ? "up" : change < 0 ? "down" : "flat",
    label: `${change > 0 ? "+" : ""}${change}`,
    // Guard against a zero baseline: "infinite growth from nothing" is not a
    // number worth showing, so callers fall back to the absolute change.
    percent: fromValue === 0 ? null : Math.round((change / fromValue) * 100),
    fromLabel: typeof from === "object" ? from.label : null,
    toLabel: typeof to === "object" ? to.label : null,
    /**
     * False when the two months compared are not consecutive, which happens
     * when the month between them had no records and so produced no bucket.
     * The caption has to admit that rather than implying month-on-month.
     */
    adjacent:
      toOrdinal != null && fromOrdinal != null ? toOrdinal - fromOrdinal === 1 : true,
  };
}
