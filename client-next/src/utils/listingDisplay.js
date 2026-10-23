/**
 * Small display rules for listing pages.
 *
 * normalizeAmenities: older listings stored the amenity list as one JSON
 * string (['[" Lift"," Gym"]']) and the page printed the brackets. The
 * backend now cleans this in its responses (backend utils/amenities.js); this
 * is the same rule on the website, for responses from builds that do not.
 *
 * amenityLabel: "powerBackup" becomes "Power Backup"; names that already have
 * spaces or are acronyms ("CCTV") are left as written.
 *
 * isBlankValue: a fact row with nothing to say ("N/A", "N/A sq.ft", empty)
 * is hidden rather than shown.
 */

export function normalizeAmenities(value) {
  const out = [];
  const collect = (v, depth) => {
    if (v == null || depth > 3) return;
    if (Array.isArray(v)) { v.forEach((item) => collect(item, depth + 1)); return; }
    if (typeof v !== 'string') return;
    const text = v.trim();
    if (!text) return;
    if (text.startsWith('[') && text.endsWith(']')) {
      try { collect(JSON.parse(text), depth + 1); return; } catch { /* keep as a name */ }
    }
    out.push(text);
  };
  collect(value, 0);
  const seen = new Set();
  return out.filter((name) => {
    const key = name.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function amenityLabel(name) {
  const text = String(name ?? '').trim();
  if (!text || /\s/.test(text)) return text;
  const spaced = text.replace(/([a-z])([A-Z])/g, '$1 $2');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function isBlankValue(value) {
  if (value == null) return true;
  if (typeof value === 'number') return !Number.isFinite(value);
  if (typeof value !== 'string') return false; // elements and other nodes are content
  const text = value.trim();
  return text === '' || /^(n\/?a|null|undefined)\b/i.test(text);
}
