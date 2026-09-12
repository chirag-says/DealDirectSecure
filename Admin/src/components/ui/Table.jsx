import React from "react";
import cn from "./cn";

/**
 * Table primitives.
 *
 * Density is the point. Rows are 12px vertical padding rather than 16px, which
 * puts three or four more records on a laptop screen, and the horizontal
 * rhythm is a single 16px gutter instead of 24px.
 *
 * Rows are separated by a hairline and nothing else. Zebra striping fights the
 * status badges for attention, so it is not here.
 */

/** Wrap in `<TableWrap>` so a wide table scrolls without breaking the card. */
export function TableWrap({ className, children }) {
  return (
    <div className={cn("overflow-x-auto", className)}>{children}</div>
  );
}

export function Table({ className, children }) {
  return (
    <table className={cn("min-w-full type-body border-collapse", className)}>
      {children}
    </table>
  );
}

export function THead({ children, sticky = false }) {
  return (
    <thead
      className={cn(
        "bg-surface-sunken",
        sticky && "sticky top-0 z-10"
      )}
    >
      {children}
    </thead>
  );
}

export function TH({ className, align = "left", children, ...props }) {
  return (
    <th
      scope="col"
      className={cn(
        "px-4 py-2.5 type-micro text-ink-muted",
        "border-b border-line whitespace-nowrap",
        align === "right" && "text-right",
        align === "center" && "text-center",
        align === "left" && "text-left",
        className
      )}
      {...props}
    >
      {children}
    </th>
  );
}

export function TBody({ className, children }) {
  return (
    <tbody className={cn("divide-y divide-line", className)}>{children}</tbody>
  );
}

export function TR({ className, children, ...props }) {
  return (
    <tr
      className={cn("transition-colors duration-75 hover:bg-surface-hover", className)}
      {...props}
    >
      {children}
    </tr>
  );
}

/**
 * `numeric` right-aligns and applies tabular figures, so a column of prices
 * or counts lines up at the decimal instead of ragging.
 */
export function TD({ className, numeric = false, children, ...props }) {
  return (
    <td
      className={cn(
        "px-4 py-3 text-ink-body align-middle",
        numeric && "text-right tabular",
        className
      )}
      {...props}
    >
      {children}
    </td>
  );
}

export default Table;
