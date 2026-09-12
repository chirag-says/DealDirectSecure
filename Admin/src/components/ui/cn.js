/**
 * Joins class names, dropping falsy entries.
 *
 * Deliberately not `tailwind-merge`: the primitives in this folder own their
 * own base classes and expose variants, so callers should be picking a variant
 * rather than passing a class that has to defeat one. `className` is for
 * layout (width, margin, grid placement), which never conflicts.
 */
export function cn(...parts) {
  return parts.filter(Boolean).join(" ");
}

export default cn;
