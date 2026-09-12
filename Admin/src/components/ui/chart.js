/**
 * Chart theme.
 *
 * Recharts takes colours as props, not classes, so the tokens have to exist in
 * JS as well. These are the same values as the CSS custom properties in
 * `index.css` — if you change one, change both.
 *
 * The rule the old dashboard broke: a chart of ONE measure gets ONE colour.
 * Six hues across six series says the series are unrelated categories, and
 * when they are actually "properties per month" that is a lie told in colour.
 */

export const CHART = {
  /** Single-measure series (properties over time, users over time, …). */
  series: "#2563eb",
  seriesFill: "rgba(37, 99, 235, 0.10)",

  /** Second measure on the same axes, when there genuinely is one. */
  seriesAlt: "#7d8fa6",
  seriesAltFill: "rgba(125, 143, 166, 0.10)",

  grid: "#eef0f3",
  axis: "#6b7480",

  /** Recharts renders the tooltip inline, so it needs literal styles. */
  tooltip: {
    backgroundColor: "#ffffff",
    border: "1px solid #e6e8eb",
    borderRadius: "8px",
    boxShadow: "0 6px 16px -4px rgba(16, 24, 40, 0.12)",
    fontSize: "12px",
    padding: "8px 10px",
  },
  tooltipLabel: { color: "#14181f", fontWeight: 600, marginBottom: 2 },
  tick: { fontSize: 11, fill: "#6b7480" },
  cursor: { fill: "rgba(37, 99, 235, 0.06)" },
};

/**
 * Colours for a breakdown of pipeline status.
 *
 * These are the Badge tones, not an arbitrary palette, so a slice of the donut
 * and the pill in the table below it agree about what "converted" looks like.
 * Ordered stages that carry no verdict yet use a blue ramp that darkens as the
 * lead advances, which makes the funnel readable without a legend.
 */
const STATUS_CHART_COLORS = {
  new: "#93b4fd",
  contacted: "#5b8def",
  negotiating: "#a16207",
  qualified: "#2563eb",
  converted: "#15803d",
  closed: "#15803d",
  rejected: "#b42318",
  lost: "#b42318",
  expired: "#b42318",
  pending: "#a16207",
  approved: "#15803d",
};

/** Fallback ramp for breakdowns that are not statuses. Ordered, not rainbow. */
const NEUTRAL_RAMP = ["#2563eb", "#5b8def", "#93b4fd", "#c2d5fd", "#8c96a3", "#c2c8d0"];

export function statusChartColor(name, index = 0) {
  const key = String(name ?? "").toLowerCase();
  return STATUS_CHART_COLORS[key] ?? NEUTRAL_RAMP[index % NEUTRAL_RAMP.length];
}

export default CHART;
