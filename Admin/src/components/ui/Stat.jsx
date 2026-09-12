import React from "react";
import { ArrowDown, ArrowUp, Minus } from "lucide-react";
import cn from "./cn";
import { Sparkline } from "./Sparkline";
import { hasPartialTail, seriesDelta } from "./series";

/**
 * A metric tile.
 *
 * The first version of this was four numbers in four boxes, and on a wide
 * screen that is a lot of white space guarding one two-digit figure. The tile
 * earns its area by carrying the shape of the number as well as the number:
 * the value, how it moved between the last two settled periods, and the run
 * of periods behind it.
 *
 * Reading order is deliberate and top to bottom: what this is, what it is
 * now, which way it went, where it has been, what that is against. Four type
 * roles, three sizes, one weight jump — the size does the ranking so nothing
 * needs colour to stand out.
 *
 * Colour appears in exactly two places: the delta, where up and down mean
 * something, and `tone`, which a caller sets when the number is a queue that
 * needs draining.
 */

const TREND = {
  up: { icon: ArrowUp, className: "text-ok" },
  down: { icon: ArrowDown, className: "text-danger" },
  flat: { icon: Minus, className: "text-ink-muted" },
};

/**
 * `tone` colours the value itself. Reserve it for numbers that are a call to
 * action — a pending queue with items in it — and leave the rest neutral, or
 * the row goes back to being a rainbow.
 */
const VALUE_TONES = {
  default: "text-ink",
  warn: "text-warn",
  danger: "text-danger",
};

const SPARK_COLORS = {
  default: "var(--color-accent)",
  warn: "var(--color-warn)",
  danger: "var(--color-danger)",
};

export function Stat({
  label,
  value,
  hint,
  icon: Icon,
  series,
  seriesLabel,
  tone = "default",
  onClick,
  className,
}) {
  const delta = seriesDelta(series);
  const Trend = delta ? TREND[delta.trend] : null;
  const partial = hasPartialTail(series);

  // Naming both months is what makes the comparison honest — "down 25%" on
  // its own hides which two periods produced it.
  const comparison =
    delta?.fromLabel && delta?.toLabel
      ? `${delta.toLabel} vs ${delta.fromLabel}`
      : null;

  const deltaTitle = delta
    ? [
      comparison
        ? `${delta.label} between ${delta.fromLabel} and ${delta.toLabel}`
        : `${delta.label} against the previous period`,
      delta.adjacent ? null : "Months in between had no records.",
      partial ? "The current month is still in progress and is excluded." : null,
    ]
      .filter(Boolean)
      .join(" ")
    : undefined;

  const caption = [hint, comparison].filter(Boolean).join(" · ");

  const body = (
    <>
      {/* 1. What this is. Smallest and quietest thing in the tile. */}
      <div className="flex items-center gap-1.5">
        {Icon && (
          <Icon className="h-3.5 w-3.5 text-ink-faint shrink-0" aria-hidden="true" />
        )}
        <span className="type-label text-ink-muted truncate">{label}</span>
      </div>

      {/* 2. What it is now, and 3. which way it went. The delta sits on the
             value's baseline so the pair reads as one statement. */}
      <div className="mt-2.5 flex items-baseline gap-2">
        <span className={cn("type-metric", VALUE_TONES[tone] ?? VALUE_TONES.default)}>
          {value}
        </span>

        {delta && (
          <span
            className={cn(
              "inline-flex items-center gap-0.5 type-label tabular",
              Trend.className
            )}
            title={deltaTitle}
          >
            <Trend.icon className="h-3 w-3 shrink-0" />
            {delta.percent != null ? `${Math.abs(delta.percent)}%` : delta.label}
          </span>
        )}
      </div>

      {/* 4. Where it has been. Takes the horizontal room the tile has going
             spare, which is the whole reason the old layout felt empty. */}
      {series && (
        <div className="mt-3 -mx-0.5">
          <Sparkline
            data={series}
            partial={partial}
            color={SPARK_COLORS[tone] ?? SPARK_COLORS.default}
          />
        </div>
      )}

      {/* 5. What that is against. `mt-auto` bottoms it out: tiles in a grid
             row stretch to the tallest, and a tile without a sparkline would
             otherwise leave its caption floating mid-card while its
             neighbours' sat at the bottom. */}
      {(caption || seriesLabel) && (
        <p
          className="mt-auto pt-2 type-label text-ink-muted truncate"
          title={seriesLabel ? `Trend shows ${seriesLabel}` : undefined}
        >
          {caption || seriesLabel}
        </p>
      )}
    </>
  );

  const base =
    "bg-surface border border-line rounded-card px-4 py-3.5 flex flex-col";

  if (typeof onClick !== "function") {
    return <div className={cn(base, className)}>{body}</div>;
  }

  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        base,
        "text-left w-full transition-colors duration-100",
        "hover:border-line-strong hover:bg-surface-hover",
        className
      )}
    >
      {body}
    </button>
  );
}

export default Stat;
