import React from "react";
import { Loader2 } from "lucide-react";
import cn from "./cn";

/**
 * The panel's only button.
 *
 * Four variants, and the choice between them is about consequence, not looks:
 *   primary   — the one action the screen exists for. At most one per view.
 *   secondary — everything else that is safe and reversible.
 *   ghost     — icon buttons and toolbar actions that sit inside other chrome.
 *   danger    — destroys or rejects something. Never the default.
 */

const VARIANTS = {
  primary:
    "bg-accent text-white border border-accent hover:bg-accent-hover hover:border-accent-hover",
  secondary:
    "bg-surface text-ink-body border border-line-strong hover:bg-surface-hover hover:text-ink",
  ghost:
    "bg-transparent text-ink-muted border border-transparent hover:bg-surface-hover hover:text-ink",
  danger:
    "bg-danger text-white border border-danger hover:brightness-110",
};

const SIZES = {
  sm: "h-8 px-2.5 gap-1.5 text-xs",
  md: "h-9 px-3 gap-2 text-sm",
};

const ICON_SIZES = { sm: "h-3.5 w-3.5", md: "h-4 w-4" };

export function Button({
  variant = "secondary",
  size = "md",
  icon: Icon,
  loading = false,
  disabled = false,
  className,
  children,
  as: Component = "button",
  ...props
}) {
  const isDisabled = disabled || loading;

  return (
    <Component
      // Native buttons default to type="submit", which silently submits any
      // form they happen to sit inside. Only set it when we are actually a
      // <button>, so `as={Link}` does not receive a stray DOM attribute.
      {...(Component === "button" ? { type: props.type || "button" } : null)}
      disabled={Component === "button" ? isDisabled : undefined}
      aria-disabled={isDisabled || undefined}
      className={cn(
        "inline-flex items-center justify-center rounded-control font-medium whitespace-nowrap",
        "transition-colors duration-100",
        "disabled:opacity-50 disabled:pointer-events-none",
        VARIANTS[variant],
        SIZES[size],
        className
      )}
      {...props}
    >
      {loading ? (
        <Loader2 className={cn(ICON_SIZES[size], "animate-spin")} />
      ) : (
        Icon && <Icon className={ICON_SIZES[size]} />
      )}
      {children}
    </Component>
  );
}

export default Button;
