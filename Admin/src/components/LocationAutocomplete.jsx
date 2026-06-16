import React, { useState, useEffect, useRef, useMemo } from "react";

/**
 * Reusable searchable combobox (input + suggestion list + keyboard nav).
 *
 * Props:
 *   value         (string)             — current input text
 *   onChange(text)                     — fires on every keystroke
 *   onSelect(item)                     — fires when a suggestion is clicked / Enter pressed
 *   suggestions   (array)              — pre-computed by parent (item shape: { label, ... })
 *   placeholder   (string)
 *   required      (bool)
 *   error         (string)             — inline error text
 *   icon          (ReactNode)          — optional leading icon
 *   disabled      (bool)
 *   className     (string)             — extra classes for the wrapper
 */
export default function LocationAutocomplete({
  value,
  onChange,
  onSelect,
  suggestions = [],
  placeholder = "",
  required = false,
  error = "",
  icon = null,
  disabled = false,
  className = "",
}) {
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(-1);
  const wrapRef = useRef(null);
  const inputRef = useRef(null);

  // Close on outside click
  useEffect(() => {
    const handler = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOpen(false);
        setHighlight(-1);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Reset highlight when suggestions change
  useEffect(() => {
    setHighlight(suggestions.length > 0 ? 0 : -1);
  }, [suggestions]);

  const handleKeyDown = (e) => {
    if (!open || suggestions.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlight((h) => (h + 1) % suggestions.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlight((h) => (h <= 0 ? suggestions.length - 1 : h - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (highlight >= 0 && highlight < suggestions.length) {
        onSelect(suggestions[highlight]);
        setOpen(false);
        setHighlight(-1);
      }
    } else if (e.key === "Escape") {
      setOpen(false);
      setHighlight(-1);
    }
  };

  // Highlight matching substring in label
  const renderLabel = (label) => {
    const q = (value || "").trim();
    if (!q) return label;
    const lower = label.toLowerCase();
    const idx = lower.indexOf(q.toLowerCase());
    if (idx === -1) return label;
    return (
      <>
        {label.slice(0, idx)}
        <mark className="bg-yellow-100 text-gray-900 rounded px-0.5">
          {label.slice(idx, idx + q.length)}
        </mark>
        {label.slice(idx + q.length)}
      </>
    );
  };

  return (
    <div ref={wrapRef} className={`relative ${className}`}>
      <div className="relative">
        {icon && (
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none">
            {icon}
          </span>
        )}
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            setOpen(true);
          }}
          onFocus={() => {
            setOpen(true);
            if (highlight === -1 && suggestions.length > 0) setHighlight(0);
          }}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          required={required}
          disabled={disabled}
          autoComplete="off"
          className={`w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed ${
            icon ? "pl-9" : ""
          } ${error ? "border-red-400" : "border-gray-300"}`}
        />
        {open && suggestions.length > 0 && (
          <ul
            role="listbox"
            className="absolute z-50 mt-1 w-full max-h-60 overflow-auto bg-white border border-gray-200 rounded-lg shadow-lg"
          >
            {suggestions.map((s, i) => (
              <li
                key={s.key || `${s.label}-${i}`}
                role="option"
                aria-selected={i === highlight}
                onMouseDown={(e) => {
                  e.preventDefault();
                  onSelect(s);
                  setOpen(false);
                  setHighlight(-1);
                }}
                onMouseEnter={() => setHighlight(i)}
                className={`px-3 py-2 text-sm cursor-pointer ${
                  i === highlight ? "bg-blue-50 text-blue-700" : "text-gray-700 hover:bg-gray-50"
                }`}
              >
                {s.secondary ? (
                  <div>
                    <div className="font-medium">{renderLabel(s.label)}</div>
                    <div className="text-xs text-gray-500">{s.secondary}</div>
                  </div>
                ) : (
                  renderLabel(s.label)
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
      {error && <p className="text-xs text-red-500 mt-1">{error}</p>}
    </div>
  );
}
