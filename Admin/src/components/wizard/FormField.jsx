import React from "react";

/**
 * FormField — a single label + input/select/textarea + inline error block.
 *
 * Props:
 *   label       {string}                        — field label text
 *   required    {boolean}                       — appends " *" to label
 *   error       {string|undefined}              — error message; triggers red border
 *   hint        {string|undefined}              — helper text below the input
 *   children    {ReactNode}                     — the actual <input>, <select>, or <textarea>
 *   dataField   {string|undefined}              — forwarded as data-field on the wrapper (for scroll-to-error)
 *   className   {string|undefined}              — extra classes on the wrapper div
 */
export default function FormField({ label, required, error, hint, children, dataField, className = "" }) {
  return (
    <div className={`space-y-1 ${className}`} data-field={dataField}>
      {label && (
        <label className="block text-sm font-medium text-gray-700">
          {label}
          {required && <span className="text-red-500 ml-0.5">*</span>}
        </label>
      )}
      {/* Clone children and inject error-aware class if it's a native input/select/textarea */}
      {React.Children.map(children, child => {
        if (!child) return child;
        const isNativeEl = ["input", "select", "textarea"].includes(child.type);
        if (!isNativeEl) return child;
        return React.cloneElement(child, {
          "aria-invalid": error ? "true" : undefined,
          "aria-describedby": error ? `${dataField}-error` : undefined,
          className: [
            child.props.className || "",
            error
              ? "border-red-400 focus:ring-red-300 bg-red-50/20"
              : "",
          ].join(" ").trim(),
        });
      })}
      {error && (
        <p id={`${dataField}-error`} role="alert" className="text-xs text-red-500 mt-1 flex items-center gap-1">
          <svg className="w-3 h-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          {error}
        </p>
      )}
      {hint && !error && (
        <p className="text-xs text-gray-400">{hint}</p>
      )}
    </div>
  );
}

/**
 * Shared class strings for inputs across all wizards.
 * Import and use in your step renderers:
 *   import { inp, lbl } from "../components/wizard/FormField";
 */
export const inp = "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors";
export const lbl = "block text-sm font-medium text-gray-700 mb-1";
