import React, { useId } from "react";
import cn from "./cn";
import { seriesValues } from "./series";

/**
 * A trend line small enough to live inside a metric tile.
 *
 * Hand-rolled SVG rather than a Recharts chart: four of these render on the
 * dashboard above the fold, and each Recharts instance brings a
 * ResponsiveContainer, a resize observer, and an axis layout pass to draw
 * what is ultimately one polyline.
 *
 * The line stretches to fill its box (`preserveAspectRatio="none"`), which
 * would normally smear the stroke along with it — `vector-effect` keeps the
 * stroke at a true 1.5px in both directions.
 */
export function Sparkline({
  data,
  color = "var(--color-accent)",
  className,
  height = 32,
  /**
   * Marks the final point as still accumulating — the current month, part way
   * through. The segment leading into it is drawn dashed and its marker is
   * hollow, so a provisional figure never reads as a settled one.
   */
  partial = false,
}) {
  const gradientId = useId();

  const values = seriesValues(data);

  // One point is not a trend, and drawing a flat line for it implies history
  // the data does not have.
  if (values.length < 2) return null;

  const W = 100;
  const H = 32;
  const PAD = 3; // keeps the stroke and its cap inside the viewBox

  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const step = W / (values.length - 1);

  const points = values.map((v, i) => {
    const x = i * step;
    const y = H - PAD - ((v - min) / span) * (H - PAD * 2);
    return [x, y];
  });

  const toPath = (pts) => pts.map(([x, y]) => `${x},${y}`).join(" ");

  // With a partial tail the solid run stops at the last settled point and a
  // dashed segment carries on to the provisional one.
  const settled = partial ? points.slice(0, -1) : points;
  const trailing = partial ? points.slice(-2) : null;

  const line = toPath(settled);
  const area = `0,${H} ${toPath(points)} ${W},${H}`;
  const [lastX, lastY] = points[points.length - 1];

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className={cn("w-full block", className)}
      style={{ height }}
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.20" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>

      <polygon points={area} fill={`url(#${gradientId})`} />

      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />

      {trailing && (
        <polyline
          points={toPath(trailing)}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          strokeDasharray="3 2.5"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />
      )}

      {/* The most recent point, marked. It is the one the operator is
          actually looking for — hollow while it is still accumulating. */}
      <circle
        cx={lastX}
        cy={lastY}
        r="2"
        fill={partial ? "var(--color-surface)" : color}
        stroke={partial ? color : "none"}
        strokeWidth={partial ? 1.25 : 0}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}


export default Sparkline;
