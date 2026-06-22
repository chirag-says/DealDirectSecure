import React from "react";
import { AlertTriangle, X } from "lucide-react";

/**
 * ConfirmModal — styled replacement for window.confirm().
 *
 * Props:
 *   title        {string}            — modal heading
 *   message      {string}            — body text
 *   confirmLabel {string}            — confirm button text (default: "Confirm")
 *   cancelLabel  {string}            — cancel button text (default: "Cancel")
 *   variant      {"danger"|"warn"}   — "danger" = red confirm button (default), "warn" = amber
 *   onConfirm    {() => void}
 *   onCancel     {() => void}
 *
 * Usage:
 *   const [confirmState, setConfirmState] = useState(null);
 *   // to show:
 *   setConfirmState({ title: "Delete?", message: "...", onConfirm: () => doDelete() });
 *   // in JSX:
 *   {confirmState && <ConfirmModal {...confirmState} onCancel={() => setConfirmState(null)} />}
 */
export default function ConfirmModal({
  title = "Are you sure?",
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "danger",
  onConfirm,
  onCancel,
}) {
  const btnClass =
    variant === "danger"
      ? "bg-red-600 hover:bg-red-700 text-white"
      : "bg-amber-500 hover:bg-amber-600 text-white";

  // Trap focus inside modal on mount
  React.useEffect(() => {
    const prev = document.activeElement;
    return () => prev?.focus();
  }, []);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onCancel()}
    >
      <div className="bg-white rounded-2xl shadow-2xl border border-gray-200 w-full max-w-sm overflow-hidden">
        {/* Header */}
        <div className="flex items-start gap-4 p-6 border-b border-gray-100">
          <div className={`p-2 rounded-xl flex-shrink-0 ${variant === "danger" ? "bg-red-50 text-red-600" : "bg-amber-50 text-amber-600"}`}>
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 id="confirm-title" className="text-base font-bold text-gray-900">{title}</h2>
            {message && <p className="text-sm text-gray-500 mt-1 leading-relaxed">{message}</p>}
          </div>
          <button
            onClick={onCancel}
            className="text-gray-400 hover:text-gray-600 p-1 rounded-lg hover:bg-gray-100 transition-colors flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {/* Actions */}
        <div className="flex gap-3 p-4">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2.5 border border-gray-200 text-gray-700 rounded-xl text-sm font-semibold hover:bg-gray-50 transition-colors"
          >
            {cancelLabel}
          </button>
          <button
            autoFocus
            onClick={() => { onConfirm(); onCancel(); }}
            className={`flex-1 px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors ${btnClass}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
