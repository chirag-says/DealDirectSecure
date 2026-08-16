/**
 * Neutralise regex metacharacters in user-supplied search input.
 *
 * Lifted verbatim from propertyController.js, which was the only place that got
 * this right. Every other search path interpolated the raw query into a
 * `$regex` or `new RegExp()`, so a caller could supply a pattern rather than a
 * search term. The worst of those was `GET /api/projects?city=` — public,
 * unauthenticated, and rate-limited only by the global 500-per-15-minutes
 * limiter, so a catastrophic-backtracking pattern could pin a CPU core.
 *
 * This is deliberately one shared implementation. Three separate copies of this
 * logic existed at one point; the ones that were missing are what this closes.
 *
 * Escaping only changes how the input is INTERPRETED, never what it matches
 * literally: a search for "3+1 BHK" still finds "3+1 BHK", it just stops "+"
 * meaning "one or more". Substring matching, case-insensitivity and result
 * ordering are unaffected.
 *
 * @param {string} string - raw user input
 * @returns {string} safe to embed in a RegExp or $regex
 */
export const escapeRegExp = (string) => {
  if (!string || typeof string !== 'string') return '';
  // Escape all regex special characters: \ ^ $ . * + ? ( ) [ ] { } |
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

export default escapeRegExp;
