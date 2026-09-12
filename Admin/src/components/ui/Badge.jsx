import React from "react";
import cn from "./cn";
import { toneForStatus } from "./status";

/**
 * Status badge.
 *
 * Five tones, and each one is a claim about the record rather than a colour
 * choice: ok = settled favourably, warn = waiting on us, danger = rejected or
 * broken, info = in flight, neutral = no state worth colouring.
 *
 * Anything that is not one of those should be plain text.
 */

const TONES = {
  ok: "bg-ok-soft text-ok border-ok-line",
  warn: "bg-warn-soft text-warn border-warn-line",
  danger: "bg-danger-soft text-danger border-danger-line",
  info: "bg-accent-soft text-accent border-accent-line",
  neutral: "bg-neutral-soft text-ink-muted border-neutral-line",
};

export function Badge({ tone = "neutral", className, children }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-control border px-1.5 py-0.5",
        "type-micro whitespace-nowrap",
        TONES[tone] ?? TONES.neutral,
        className
      )}
    >
      {children}
    </span>
  );
}

/** Badge that picks its own tone from a status string. */
export function StatusBadge({ status, className }) {
  return (
    <Badge tone={toneForStatus(status)} className={className}>
      {String(status ?? "unknown").replace(/[_-]/g, " ")}
    </Badge>
  );
}

export default Badge;
