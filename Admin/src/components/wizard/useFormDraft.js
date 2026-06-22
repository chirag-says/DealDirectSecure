import { useState, useEffect, useRef } from "react";

/**
 * useFormDraft — persists form state to localStorage with a 24-hour TTL.
 * File objects are automatically excluded (they can't survive JSON serialization).
 *
 * @param {string} draftKey  - unique localStorage key (e.g. "createProjectDraft_<builderId>")
 * @param {boolean} enabled  - set false in edit mode (source of truth is the DB)
 * @returns {{ draftExists, saveDraft, loadDraft, clearDraft }}
 */
export function useFormDraft(draftKey, enabled = true) {
  const [draftExists, setDraftExists] = useState(false);
  const saveTimeoutRef = useRef(null);
  const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Save form state + current step. Debounced by 1 s to avoid thrashing localStorage.
   * @param {object} form   - top-level form state (File values are stripped)
   * @param {number} step   - current wizard step
   */
  const saveDraft = (form, step) => {
    if (!enabled || !draftKey) return;
    clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => {
      // Strip File objects — they don't survive serialization
      const serializable = {};
      for (const [k, v] of Object.entries(form)) {
        if (v instanceof File || (Array.isArray(v) && v[0] instanceof File)) continue;
        serializable[k] = v;
      }
      try {
        localStorage.setItem(draftKey, JSON.stringify({ form: serializable, step, timestamp: Date.now() }));
        setDraftExists(true);
      } catch {
        // Quota exceeded — silently ignore
      }
    }, 1000);
  };

  /**
   * Load draft from localStorage.
   * Returns { form, step } if a valid, non-expired draft exists, otherwise null.
   */
  const loadDraft = () => {
    if (!enabled || !draftKey) return null;
    try {
      const raw = localStorage.getItem(draftKey);
      if (!raw) return null;
      const draft = JSON.parse(raw);
      if (!draft.step || Date.now() - draft.timestamp >= TTL_MS) {
        localStorage.removeItem(draftKey);
        return null;
      }
      setDraftExists(true);
      return { form: draft.form, step: draft.step };
    } catch {
      return null;
    }
  };

  /** Remove the draft from localStorage and reset the indicator flag. */
  const clearDraft = () => {
    if (!draftKey) return;
    localStorage.removeItem(draftKey);
    setDraftExists(false);
  };

  // Clean up any pending save on unmount
  useEffect(() => () => clearTimeout(saveTimeoutRef.current), []);

  return { draftExists, saveDraft, loadDraft, clearDraft };
}
