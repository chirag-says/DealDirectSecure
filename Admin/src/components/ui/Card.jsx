import React from "react";
import cn from "./cn";

/**
 * A bordered panel. No shadow: on a page holding eight or nine of these,
 * shadows read as haze. A 1px line separates just as well and stays crisp.
 */
export function Card({ className, children, ...props }) {
  return (
    <div
      className={cn(
        "bg-surface border border-line rounded-card",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

/**
 * Card header. `action` is the slot for the one control that belongs to this
 * panel — a "view all" link, a range picker, an export button.
 */
export function CardHeader({ title, subtitle, action, className, children }) {
  return (
    <div
      className={cn(
        "flex items-start justify-between gap-4 px-4 py-3 border-b border-line",
        className
      )}
    >
      <div className="min-w-0">
        <h2 className="type-card text-ink truncate">{title}</h2>
        {subtitle && (
          <p className="type-label text-ink-muted mt-0.5 truncate">{subtitle}</p>
        )}
      </div>
      {action ?? children}
    </div>
  );
}

export function CardBody({ className, children, ...props }) {
  return (
    <div className={cn("p-4", className)} {...props}>
      {children}
    </div>
  );
}

export default Card;
