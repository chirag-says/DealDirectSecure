import React from "react";
import { Loader2 } from "lucide-react";
import cn from "./cn";

/**
 * The three states every screen in the panel has to render besides "here is
 * your data": loading, empty, and page-level heading. Each was previously
 * re-invented per page, which is why no two looked alike.
 */

/** Page title bar. `actions` holds the controls that apply to the whole page. */
export function PageHeader({ title, subtitle, actions, className }) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-5",
        className
      )}
    >
      <div className="min-w-0">
        <h1 className="type-page text-ink">{title}</h1>
        {subtitle && (
          <p className="type-label text-ink-muted mt-1">{subtitle}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/**
 * Empty state.
 *
 * States what is missing and, where there is one, offers the action that would
 * fix it. No illustration and no oversized icon: an operator sees these a
 * dozen times a day and does not need to be consoled.
 */
export function EmptyState({ icon: Icon, title, description, action, className }) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center px-6 py-12",
        className
      )}
    >
      {Icon && <Icon className="h-5 w-5 text-ink-faint mb-2.5" aria-hidden="true" />}
      <p className="type-body font-medium text-ink-body">{title}</p>
      {description && (
        <p className="type-label text-ink-muted mt-1 max-w-xs">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** Inline spinner for a region that is still loading. */
export function Loading({ label = "Loading", className }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex flex-col items-center justify-center gap-2 py-12 text-ink-muted",
        className
      )}
    >
      <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />
      <span className="type-label">{label}</span>
    </div>
  );
}

/**
 * Skeleton block. Used where we know the shape of what is coming, so the
 * layout does not jump when it arrives.
 */
export function Skeleton({ className }) {
  return (
    <div
      className={cn("animate-pulse rounded-control bg-neutral-soft", className)}
      aria-hidden="true"
    />
  );
}

export default PageHeader;
